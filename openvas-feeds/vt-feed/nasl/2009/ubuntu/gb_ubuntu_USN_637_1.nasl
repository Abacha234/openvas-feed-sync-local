# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840325");
  script_cve_id("CVE-2008-0598", "CVE-2008-2812", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 14:50:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-637-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-637-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-source-2.6.15, linux-source-2.6.20, linux-source-2.6.22' package(s) announced via the USN-637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were multiple NULL-pointer function
dereferences in the Linux kernel terminal handling code. A local attacker
could exploit this to execute arbitrary code as root, or crash the system,
leading to a denial of service. (CVE-2008-2812)

The do_change_type routine did not correctly validation administrative
users. A local attacker could exploit this to block mount points or cause
private mounts to be shared, leading to denial of service or a possible
loss of privacy. (CVE-2008-2931)

Tobias Klein discovered that the OSS interface through ALSA did not
correctly validate the device number. A local attacker could exploit this
to access sensitive kernel memory, leading to a denial of service or a loss
of privacy. (CVE-2008-3272)

Zoltan Sogor discovered that new directory entries could be added to
already deleted directories. A local attacker could exploit this, filling
up available memory and disk space, leading to a denial of service.
(CVE-2008-3275)

In certain situations, the fix for CVE-2008-0598 from USN-623-1 was causing
infinite loops in the writev syscall. This update corrects the mistake. We
apologize for the inconvenience.");

  script_tag(name:"affected", value:"'linux, linux-source-2.6.15, linux-source-2.6.20, linux-source-2.6.22' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
