// SPDX-License-Identifier: GPL-2.0
/*
 * sil6250 - Silead SIL6250 fingerprint mailbox resource broker.
 *
 * Minimal ACPI platform driver for the SIL6250 sensor as wired on the Huawei
 * MateBook X Pro 2024 (ACPI HID "SIL6250"). The sensor is reached through an
 * EC-arbitrated shared-memory mailbox (ACPI _CRS Memory32Fixed) + two GpioIo
 * strobe outputs and one GpioInt RX-ready doorbell.
 *
 * This driver intentionally contains no protocol knowledge. It only:
 *   - binds the ACPI device and ioremaps the mailbox window,
 *   - resolves and claims the two GpioIo outputs + the GpioInt,
 *   - hands all three to userspace through /dev/sil6250 (mmap + 2 ioctls).
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "sil6250_uapi.h"

#define SIL6250_DRV_NAME "sil6250"
#define SIL6250_WAIT_DEFAULT_MS	500
#define SIL6250_WAIT_MAX_MS	30000

struct sil6250 {
	struct device *dev;

	phys_addr_t window_phys;
	resource_size_t window_size;
	void __iomem *window;

	struct gpio_desc *gpio_write_done;
	struct gpio_desc *gpio_read_done;
	struct gpio_desc *gpio_irq;
	int irq;

	/* RX-ready GpioInt is level-high: masked after each fire, re-armed by
	 * SIL6250_WAIT_IRQ before the next wait (see sil6250_wait_irq). */
	struct completion rx_irq;
	bool irq_masked;
	struct mutex irq_lock;
	atomic_t users;
	wait_queue_head_t users_wait;
	struct mutex lifecycle_lock;
	bool removing;

	struct miscdevice misc;
};

/* ---- ACPI _CRS GPIO resolution -------------------------------------------
 *
 * The _CRS lists one GpioInt (RX doorbell) and two GpioIo outputs (the strobes)
 * but does not name them, so we discover their resource indices and install an
 * ACPI driver-GPIO mapping to fetch them by name.
 */
struct sil6250_crs {
	int gpio_seen;
	int io_seen;
	u8  io_pol[2];
	int io_index[2];
	int int_index;
};

static int sil6250_crs_cb(struct acpi_resource *ares, void *context)
{
	struct sil6250_crs *st = context;
	struct acpi_resource_gpio *g;

	if (!ares || ares->type != ACPI_RESOURCE_TYPE_GPIO)
		return 0;

	g = &ares->data.gpio;
	st->gpio_seen++;

	if (g->connection_type == ACPI_RESOURCE_GPIO_TYPE_INT) {
		if (st->int_index < 0)
			st->int_index = st->gpio_seen - 1;
	} else if (g->connection_type == ACPI_RESOURCE_GPIO_TYPE_IO) {
		if (st->io_seen < 2) {
			st->io_pol[st->io_seen] = g->polarity;
			st->io_index[st->io_seen] = st->gpio_seen - 1;
			st->io_seen++;
		}
	}
	return 0;
}

static int sil6250_add_gpio_mapping(struct platform_device *pdev)
{
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);
	struct sil6250_crs st = { .int_index = -1,
				  .io_index = { -1, -1 } };
	struct acpi_gpio_params *params;
	struct acpi_gpio_mapping *map;
	LIST_HEAD(res_list);
	bool active_low;
	int rc;

	if (!adev)
		return -ENODEV;

	rc = acpi_dev_get_resources(adev, &res_list, sil6250_crs_cb, &st);
	acpi_dev_free_resource_list(&res_list);
	if (rc <= 0)
		return -ENOENT;
	if (st.int_index < 0 || st.io_seen < 2 ||
	    st.io_index[0] < 0 || st.io_index[1] < 0)
		return -ENOENT;
	if (st.io_pol[0] != st.io_pol[1]) {
		dev_warn(&pdev->dev, "_CRS: strobe GPIO polarities differ\n");
		return -EINVAL;
	}
	active_low = st.io_pol[0] ? true : false;

	params = devm_kcalloc(&pdev->dev, 3, sizeof(*params), GFP_KERNEL);
	map = devm_kcalloc(&pdev->dev, 4, sizeof(*map), GFP_KERNEL);
	if (!params || !map)
		return -ENOMEM;

	params[0].crs_entry_index = st.int_index;
	map[0].name = "irq-gpios";
	map[0].data = &params[0];
	map[0].size = 1;

	params[1].crs_entry_index = st.io_index[0];
	params[1].active_low = active_low;
	map[1].name = "write-done-gpios";
	map[1].data = &params[1];
	map[1].size = 1;

	params[2].crs_entry_index = st.io_index[1];
	params[2].active_low = active_low;
	map[2].name = "read-done-gpios";
	map[2].data = &params[2];
	map[2].size = 1;
	/* map[3] terminator (kcalloc-zeroed) */

	return devm_acpi_dev_add_driver_gpios(&pdev->dev, map);
}

static int sil6250_init_gpios(struct platform_device *pdev, struct sil6250 *s)
{
	struct gpio_desc *d;
	bool mapped = false;
	int rc;

	d = devm_gpiod_get(&pdev->dev, "write-done", GPIOD_OUT_LOW);
	if (IS_ERR(d) && PTR_ERR(d) == -ENOENT) {
		rc = sil6250_add_gpio_mapping(pdev);
		if (rc)
			return rc;
		mapped = true;
		d = devm_gpiod_get(&pdev->dev, "write-done", GPIOD_OUT_LOW);
	}
	if (IS_ERR(d))
		return PTR_ERR(d);
	s->gpio_write_done = d;

	d = devm_gpiod_get(&pdev->dev, "read-done", GPIOD_OUT_LOW);
	if (!mapped && IS_ERR(d) && PTR_ERR(d) == -ENOENT) {
		rc = sil6250_add_gpio_mapping(pdev);
		if (rc)
			return rc;
		mapped = true;
		d = devm_gpiod_get(&pdev->dev, "read-done", GPIOD_OUT_LOW);
	}
	if (IS_ERR(d))
		return PTR_ERR(d);
	s->gpio_read_done = d;

	d = devm_gpiod_get(&pdev->dev, "irq", GPIOD_IN);
	if (!mapped && IS_ERR(d) && PTR_ERR(d) == -ENOENT) {
		rc = sil6250_add_gpio_mapping(pdev);
		if (rc)
			return rc;
		d = devm_gpiod_get(&pdev->dev, "irq", GPIOD_IN);
	}
	if (IS_ERR(d))
		return PTR_ERR(d);
	s->gpio_irq = d;

	/* Windows SPBDevicePrepareHardware drives both outputs low and sleeps
	 * 5 ms before any transaction; do the same for bring-up. */
	gpiod_set_value_cansleep(s->gpio_write_done, 0);
	gpiod_set_value_cansleep(s->gpio_read_done, 0);
	msleep(5);
	return 0;
}

/* ---- IRQ ------------------------------------------------------------------ */

static irqreturn_t sil6250_irq_thread(int irq, void *data)
{
	struct sil6250 *s = data;

	/*
	 * Level-high line: mask it now so it does not re-fire while userspace
	 * processes the staged packet. SIL6250_WAIT_IRQ re-arms (enable_irq)
	 * before the next wait.
	 */
	disable_irq_nosync(s->irq);
	WRITE_ONCE(s->irq_masked, true);
	complete(&s->rx_irq);
	return IRQ_HANDLED;
}

static long sil6250_wait_irq(struct sil6250 *s, u32 timeout_ms)
{
	long jl;
	int rc;

	if (READ_ONCE(s->removing) || s->irq <= 0)
		return -ENODEV;
	if (!timeout_ms)
		timeout_ms = SIL6250_WAIT_DEFAULT_MS;
	if (timeout_ms > SIL6250_WAIT_MAX_MS)
		return -EINVAL;

	rc = mutex_lock_interruptible(&s->irq_lock);
	if (rc)
		return rc;
	mutex_lock(&s->lifecycle_lock);
	reinit_completion(&s->rx_irq);
	if (READ_ONCE(s->removing)) {
		mutex_unlock(&s->lifecycle_lock);
		mutex_unlock(&s->irq_lock);
		return -ENODEV;
	}
	mutex_unlock(&s->lifecycle_lock);

	/* Re-arm the level line. If the EC already staged a packet the line is
	 * high and the IRQ fires immediately; otherwise we wait for assertion. */
	if (READ_ONCE(s->irq_masked)) {
		WRITE_ONCE(s->irq_masked, false);
		enable_irq(s->irq);
	}
	jl = wait_for_completion_timeout(&s->rx_irq,
					 msecs_to_jiffies(timeout_ms));
	mutex_unlock(&s->irq_lock);

	if (READ_ONCE(s->removing))
		return -ENODEV;
	return jl > 0 ? 0 : -ETIMEDOUT;
}

/* ---- chardev -------------------------------------------------------------- */

static struct sil6250 *sil6250_from_file(struct file *file)
{
	return file->private_data;
}

static int sil6250_open(struct inode *inode, struct file *file)
{
	struct miscdevice *m = file->private_data;
	struct sil6250 *s = container_of(m, struct sil6250, misc);

	mutex_lock(&s->lifecycle_lock);
	if (s->removing) {
		mutex_unlock(&s->lifecycle_lock);
		return -ENODEV;
	}
	atomic_inc(&s->users);
	file->private_data = s;
	mutex_unlock(&s->lifecycle_lock);
	return 0;
}

static int sil6250_release(struct inode *inode, struct file *file)
{
	struct sil6250 *s = sil6250_from_file(file);

	if (atomic_dec_and_test(&s->users))
		wake_up_all(&s->users_wait);
	return 0;
}

static long sil6250_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sil6250 *s = sil6250_from_file(file);
	void __user *uarg = (void __user *)arg;

	if (READ_ONCE(s->removing))
		return -ENODEV;

	switch (cmd) {
	case SIL6250_SET_GPIO: {
		struct sil6250_gpio g;
		struct gpio_desc *d;

		if (copy_from_user(&g, uarg, sizeof(g)))
			return -EFAULT;
		switch (g.line) {
		case SIL6250_LINE_WRITE_DONE:
			d = s->gpio_write_done;
			break;
		case SIL6250_LINE_READ_DONE:
			d = s->gpio_read_done;
			break;
		default:
			return -EINVAL;
		}
		gpiod_set_value_cansleep(d, g.value ? 1 : 0);
		return 0;
	}
	case SIL6250_WAIT_IRQ: {
		struct sil6250_wait_irq w;

		if (copy_from_user(&w, uarg, sizeof(w)))
			return -EFAULT;
		return sil6250_wait_irq(s, w.timeout_ms);
	}
	case SIL6250_GET_WINDOW_SIZE: {
		u32 sz = (u32)s->window_size;

		if (copy_to_user(uarg, &sz, sizeof(sz)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static int sil6250_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sil6250 *s = sil6250_from_file(file);

	if (READ_ONCE(s->removing))
		return -ENODEV;

	/* MMIO window: non-cached, and only the window itself is mappable. */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return vm_iomap_memory(vma, s->window_phys, s->window_size);
}

/*
 * Access is gated by the /dev/sil6250 node permissions: the exposed surface is
 * narrow and device-scoped (mmap is clamped to this device's own MMIO window,
 * SET_GPIO drives only the two strobe lines).
 */
static const struct file_operations sil6250_fops = {
	.owner		= THIS_MODULE,
	.open		= sil6250_open,
	.release	= sil6250_release,
	.unlocked_ioctl	= sil6250_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.mmap		= sil6250_mmap,
};

/* ---- probe / remove ------------------------------------------------------- */

static int sil6250_probe(struct platform_device *pdev)
{
	struct sil6250 *s;
	struct resource *res;
	unsigned int irq_type;
	int ret;

	s = devm_kzalloc(&pdev->dev, sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->dev = &pdev->dev;
	init_completion(&s->rx_irq);
	mutex_init(&s->irq_lock);
	atomic_set(&s->users, 0);
	init_waitqueue_head(&s->users_wait);
	mutex_init(&s->lifecycle_lock);
	s->irq_masked = true;
	platform_set_drvdata(pdev, s);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "missing mailbox MMIO window\n");
		return -ENODEV;
	}
	s->window_phys = res->start;
	s->window_size = resource_size(res);
	s->window = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(s->window))
		return PTR_ERR(s->window);

	ret = sil6250_init_gpios(pdev, s);
	if (ret) {
		if (ret != -EPROBE_DEFER)
			dev_err(&pdev->dev, "GPIO setup failed (%d)\n", ret);
		return ret;
	}

	s->irq = gpiod_to_irq(s->gpio_irq);
	if (s->irq < 0)
		return dev_err_probe(&pdev->dev, s->irq, "gpiod_to_irq\n");

	irq_type = irq_get_trigger_type(s->irq);
	if (irq_type == IRQ_TYPE_NONE) {
		/* _CRS reports GpioInt(Level, ActiveHigh, ...) */
		irq_set_irq_type(s->irq, IRQ_TYPE_LEVEL_HIGH);
	}

	/* Request enabled (so the core fully sets up the line), then mask:
	 * gives a known masked initial state with a balanced first enable_irq()
	 * in SIL6250_WAIT_IRQ. */
	ret = devm_request_threaded_irq(&pdev->dev, s->irq, NULL,
					sil6250_irq_thread, IRQF_ONESHOT,
					SIL6250_DRV_NAME, s);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "request_irq\n");
	disable_irq(s->irq);
	s->irq_masked = true;

	s->misc.minor = MISC_DYNAMIC_MINOR;
	s->misc.name = SIL6250_DRV_NAME;
	s->misc.fops = &sil6250_fops;
	s->misc.parent = &pdev->dev;
	ret = misc_register(&s->misc);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "misc_register\n");

	dev_info(&pdev->dev,
		 "ready: window %pa/%pa irq=%d -> /dev/%s\n",
		 &s->window_phys, &s->window_size, s->irq, SIL6250_DRV_NAME);
	return 0;
}

static void sil6250_remove(struct platform_device *pdev)
{
	struct sil6250 *s = platform_get_drvdata(pdev);

	misc_deregister(&s->misc);
	mutex_lock(&s->lifecycle_lock);
	s->removing = true;
	complete_all(&s->rx_irq);
	mutex_unlock(&s->lifecycle_lock);
	mutex_lock(&s->irq_lock);
	if (s->irq > 0 && !READ_ONCE(s->irq_masked)) {
		disable_irq(s->irq);
		s->irq_masked = true;
	}
	mutex_unlock(&s->irq_lock);
	synchronize_irq(s->irq);
	wait_event(s->users_wait, atomic_read(&s->users) == 0);
}

static const struct acpi_device_id sil6250_acpi_ids[] = {
	{ "SIL6250", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, sil6250_acpi_ids);

static struct platform_driver sil6250_driver = {
	.driver = {
		.name = SIL6250_DRV_NAME,
		.acpi_match_table = sil6250_acpi_ids,
	},
	.probe = sil6250_probe,
	.remove = sil6250_remove,
};
module_platform_driver(sil6250_driver);

MODULE_DESCRIPTION("Silead SIL6250 fingerprint mailbox resource broker");
MODULE_AUTHOR("Alexander Daichendt");
MODULE_LICENSE("GPL");
