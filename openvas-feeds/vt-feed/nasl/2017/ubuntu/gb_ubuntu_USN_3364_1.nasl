# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843252");
  script_cve_id("CVE-2014-9900", "CVE-2015-8944", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-9150", "CVE-2017-9605");
  script_tag(name:"creation_date", value:"2017-07-25 05:24:25 +0000 (Tue, 25 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3364-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3364-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3364-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3364-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly initialize a Wake-
on-Lan data structure. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2014-9900)

It was discovered that the Linux kernel did not properly restrict access to
/proc/iomem. A local attacker could use this to expose sensitive
information. (CVE-2015-8944)

Alexander Potapenko discovered a race condition in the Advanced Linux Sound
Architecture (ALSA) subsystem in the Linux kernel. A local attacker could
use this to expose sensitive information (kernel memory).
(CVE-2017-1000380)

Li Qiang discovered that the DRM driver for VMware Virtual GPUs in the
Linux kernel did not properly validate some ioctl arguments. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-7346)

Jann Horn discovered that bpf in Linux kernel does not restrict the output
of the print_bpf_insn function. A local attacker could use this to obtain
sensitive address information. (CVE-2017-9150)

Murray McAllister discovered that the DRM driver for VMware Virtual GPUs in
the Linux kernel did not properly initialize memory. A local attacker could
use this to expose sensitive information (kernel memory). (CVE-2017-9605)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
