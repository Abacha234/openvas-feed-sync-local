# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703616");
  script_cve_id("CVE-2014-9904", "CVE-2016-5728", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6130");
  script_tag(name:"creation_date", value:"2016-07-03 22:00:00 +0000 (Sun, 03 Jul 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:16:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-3616)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3616");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3616");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3616 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2014-9904

It was discovered that the snd_compress_check_input function used in the ALSA subsystem does not properly check for an integer overflow, allowing a local user to cause a denial of service.

CVE-2016-5728

Pengfei Wang discovered a race condition in the MIC VOP driver that could allow a local user to obtain sensitive information from kernel memory or cause a denial of service.

CVE-2016-5828

Cyril Bur and Michael Ellerman discovered a flaw in the handling of Transactional Memory on powerpc systems allowing a local user to cause a denial of service (kernel crash) or possibly have unspecified other impact, by starting a transaction, suspending it, and then calling any of the exec() class system calls.

CVE-2016-5829

A heap-based buffer overflow vulnerability was found in the hiddev driver, allowing a local user to cause a denial of service or, potentially escalate their privileges.

CVE-2016-6130

Pengfei Wang discovered a flaw in the S/390 character device drivers potentially leading to information leak with /dev/sclp.

Additionally this update fixes a regression in the ebtables facility (#828914) that was introduced in DSA-3607-1.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt25-2+deb8u3.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);