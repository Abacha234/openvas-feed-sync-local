# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892494");
  script_cve_id("CVE-2020-0427", "CVE-2020-14351", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-28974", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2020-12-19 04:00:22 +0000 (Sat, 19 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 12:15:00 +0000 (Fri, 02 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2494");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2494");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to the execution of arbitrary code, privilege escalation, denial of service or information leaks.

CVE-2020-0427

Elena Petrova reported a bug in the pinctrl subsystem that can lead to a use-after-free after a device is renamed. The security impact of this is unclear.

CVE-2020-8694

Multiple researchers discovered that the powercap subsystem allowed all users to read CPU energy meters, by default. On systems using Intel CPUs, this provided a side channel that could leak sensitive information between user processes, or from the kernel to user processes. The energy meters are now readable only by root, by default.

This issue can be mitigated by running:

chmod go-r /sys/devices/virtual/powercap/*/*/energy_uj

This needs to be repeated each time the system is booted with an unfixed kernel version.

CVE-2020-14351

A race condition was discovered in the performance events subsystem, which could lead to a use-after-free. A local user permitted to access performance events could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

Debian's kernel configuration does not allow unprivileged users to access performance events by default, which fully mitigates this issue.

CVE-2020-25645

A flaw was discovered in the interface driver for GENEVE encapsulated traffic when combined with IPsec. If IPsec is configured to encrypt traffic for the specific UDP port used by the GENEVE tunnel, tunneled data isn't correctly routed over the encrypted link and sent unencrypted instead.

CVE-2020-25656

Yuan Ming and Bodong Zhao discovered a race condition in the virtual terminal (vt) driver that could lead to a use-after-free. A local user with the CAP_SYS_TTY_CONFIG capability could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-25668

Yuan Ming and Bodong Zhao discovered a race condition in the virtual terminal (vt) driver that could lead to a use-after-free. A local user with access to a virtual terminal, or with the CAP_SYS_TTY_CONFIG capability, could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-25669

Bodong Zhao discovered a bug in the Sun keyboard driver (sunkbd) that could lead to a use-after-free. On a system using this driver, a local user could use this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2020-25704

kiyin(Yin Liang ) discovered a potential memory leak in the performance events subsystem. A local user permitted to access performance events could use this to cause a denial of service (memory exhaustion).

Debian's kernel configuration does not allow unprivileged users to access performance events by default, which fully mitigates this ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);