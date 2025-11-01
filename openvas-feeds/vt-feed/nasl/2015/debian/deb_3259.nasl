# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703259");
  script_cve_id("CVE-2014-9718", "CVE-2015-1779", "CVE-2015-2756", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2015-05-12 22:00:00 +0000 (Tue, 12 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 11:40:00 +0000 (Mon, 05 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-3259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3259");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3259");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-3259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the qemu virtualisation solution:

CVE-2014-9718

It was discovered that the IDE controller emulation is susceptible to denial of service.

CVE-2015-1779

Daniel P. Berrange discovered a denial of service vulnerability in the VNC web socket decoder.

CVE-2015-2756

Jan Beulich discovered that unmediated PCI command register could result in denial of service.

CVE-2015-3456

Jason Geffner discovered a buffer overflow in the emulated floppy disk drive, resulting in the potential execution of arbitrary code.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.1.2+dfsg-6a+deb7u7 of the qemu source package and in version 1.1.2+dfsg-6+deb7u7 of the qemu-kvm source package. Only CVE-2015-3456 affects oldstable.

For the stable distribution (jessie), these problems have been fixed in version 1:2.1+dfsg-12.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);