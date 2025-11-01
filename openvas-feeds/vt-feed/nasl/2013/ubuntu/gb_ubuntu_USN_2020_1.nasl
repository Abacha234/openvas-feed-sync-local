# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841618");
  script_cve_id("CVE-2013-0343", "CVE-2013-2147", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2897", "CVE-2013-4270", "CVE-2013-4343");
  script_tag(name:"creation_date", value:"2013-11-18 10:15:27 +0000 (Mon, 18 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2020-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2020-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-raring' package(s) announced via the USN-2020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information leak was discovered in the handling of ICMPv6 Router
Advertisement (RA) messages in the Linux kernel's IPv6 network stack. A
remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently obtain
sensitive information. (CVE-2013-0343)

Dan Carpenter discovered an information leak in the HP Smart Array and
Compaq SMART2 disk-array driver in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-2147)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem
when CONFIG_HID_ZEROPLUS is enabled. A physically proximate attacker could
leverage this flaw to cause a denial of service via a specially crafted
device. (CVE-2013-2889)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physically
proximate attacker can leverage this flaw to cause a denial of service vias
a specially crafted device. (CVE-2013-2893)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel when CONFIG_HID_LENOVO_TPKBD is enabled. A physically
proximate attacker could exploit this flaw to cause a denial of service via
a specially crafted device. (CVE-2013-2894)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled. A
physically proximate attacker could cause a denial of service (OOPS) or
obtain sensitive information from kernel memory via a specially crafted
device. (CVE-2013-2895)

Kees Cook discovered yet another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is enabled. A
physically proximate attacker could leverage this flaw to cause a denial of
service (OOPS) via a specially crafted device. (CVE-2013-2897)

Miroslav Vadkerti discovered a flaw in how the permissions for network
sysctls are handled in the Linux kernel. An unprivileged local user could
exploit this flaw to have privileged access to files in /proc/sys/net/.
(CVE-2013-4270)

Wannes Rombouts reported a vulnerability in the networking tuntap interface
of the Linux kernel. A local user with the CAP_NET_ADMIN capability could
leverage this flaw to gain full admin privileges. (CVE-2013-4343)");

  script_tag(name:"affected", value:"'linux-lts-raring' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
