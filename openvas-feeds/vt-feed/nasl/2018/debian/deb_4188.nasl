# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704188");
  script_cve_id("CVE-2017-17975", "CVE-2017-18193", "CVE-2017-18216", "CVE-2017-18218", "CVE-2017-18222", "CVE-2017-18224", "CVE-2017-18241", "CVE-2017-18257", "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000199", "CVE-2018-10323", "CVE-2018-1065", "CVE-2018-1066", "CVE-2018-1068", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-5803", "CVE-2018-7480", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757", "CVE-2018-7995", "CVE-2018-8087", "CVE-2018-8781", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2018-04-30 22:00:00 +0000 (Mon, 30 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 15:10:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Debian: Security Advisory (DSA-4188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4188");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4188");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various processors supporting speculative execution, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Spectre variant 2 (branch target injection) and is mitigated for the x86 architecture (amd64 and i386) by using the retpoline compiler feature which allows indirect branches to be isolated from speculative execution.

CVE-2017-5753

Multiple researchers have discovered a vulnerability in various processors supporting speculative execution, enabling an attacker controlling an unprivileged process to read memory from arbitrary addresses, including from the kernel and all other processes running on the system.

This specific attack has been named Spectre variant 1 (bounds-check bypass) and is mitigated by identifying vulnerable code sections (array bounds checking followed by array access) and replacing the array access with the speculation-safe array_index_nospec() function.

More use sites will be added over time.

CVE-2017-17975

Tuba Yavuz reported a use-after-free flaw in the USBTV007 audio-video grabber driver. A local user could use this for denial of service by triggering failure of audio registration.

CVE-2017-18193

Yunlei He reported that the f2fs implementation does not properly handle extent trees, allowing a local user to cause a denial of service via an application with multiple threads.

CVE-2017-18216

Alex Chen reported that the OCFS2 filesystem failed to hold a necessary lock during nodemanager sysfs file operations, potentially leading to a null pointer dereference. A local user could use this for denial of service.

CVE-2017-18218

Jun He reported a use-after-free flaw in the Hisilicon HNS ethernet driver. A local user could use this for denial of service.

CVE-2017-18222

It was reported that the Hisilicon Network Subsystem (HNS) driver implementation does not properly handle ethtool private flags. A local user could use this for denial of service or possibly have other impact.

CVE-2017-18224

Alex Chen reported that the OCFS2 filesystem omits the use of a semaphore and consequently has a race condition for access to the extent tree during read operations in DIRECT mode. A local user could use this for denial of service.

CVE-2017-18241

Yunlei He reported that the f2fs implementation does not properly initialise its state if the noflush_merge mount option is used. A local user with access to a filesystem mounted with this option could use this to cause a denial of service.

CVE-2017-18257

It was reported that the f2fs implementation is prone to an infinite loop caused by an ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);