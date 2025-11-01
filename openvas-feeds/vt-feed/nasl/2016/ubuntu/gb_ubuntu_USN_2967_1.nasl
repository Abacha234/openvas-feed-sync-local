# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842741");
  script_cve_id("CVE-2013-4312", "CVE-2015-1805", "CVE-2015-7515", "CVE-2015-7566", "CVE-2015-7833", "CVE-2015-8767", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-0774", "CVE-2016-0821", "CVE-2016-2069", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-05-10 03:21:24 +0000 (Tue, 10 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-2967-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2967-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2967-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2967-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly enforce rlimits
for file descriptors sent over UNIX domain sockets. A local attacker could
use this to cause a denial of service. (CVE-2013-4312)

Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the
Linux kernel did not properly validate the endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7515)

Ralf Spenneberg discovered that the USB driver for Clie devices in the
Linux kernel did not properly validate the endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7566)

Ralf Spenneberg discovered that the usbvision driver in the Linux kernel
did not properly validate the interfaces and endpoints reported by the
device. An attacker with physical access could cause a denial of service
(system crash). (CVE-2015-7833)

It was discovered that a race condition existed when handling heartbeat-
timeout events in the SCTP implementation of the Linux kernel. A remote
attacker could use this to cause a denial of service. (CVE-2015-8767)

Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
kernel's CXGB3 driver. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

It was discovered that a race condition existed in the ioctl handler for
the TTY driver in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or expose sensitive information.
(CVE-2016-0723)

It was discovered that the Linux kernel did not keep accurate track of pipe
buffer details when error conditions occurred, due to an incomplete fix for
CVE-2015-1805. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code with administrative
privileges. (CVE-2016-0774)

Zach Riggle discovered that the Linux kernel's list poison feature did not
take into account the mmap_min_addr value. A local attacker could use this
to bypass the kernel's poison-pointer protection mechanism while attempting
to exploit an existing kernel vulnerability. (CVE-2016-0821)

Andy Lutomirski discovered a race condition in the Linux kernel's
translation lookaside buffer (TLB) handling of flush events. A local
attacker could use this to cause a denial of service or possibly leak
sensitive information. (CVE-2016-2069)

Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA)
framework did not verify that a FIFO was attached to a client before
attempting to clear it. A local attacker could use this to cause a denial
of service (system crash). (CVE-2016-2543)

Dmitry Vyukov discovered that a race condition existed in the Advanced
Linux Sound Architecture (ALSA) framework between timer setup and closing
of the client, resulting in a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
