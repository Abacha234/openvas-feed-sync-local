# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892068");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-10220", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15098", "CVE-2019-15217", "CVE-2019-15291", "CVE-2019-15505", "CVE-2019-16746", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19062", "CVE-2019-19066", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19922", "CVE-2019-19947", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-2215");
  script_tag(name:"creation_date", value:"2020-01-19 04:00:44 +0000 (Sun, 19 Jan 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-16 14:09:00 +0000 (Wed, 16 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-2068)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2068");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2068");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-2068 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, or information leak.

CVE-2019-2215

The syzkaller tool discovered a use-after-free vulnerability in the Android binder driver. A local user on a system with this driver enabled could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation. However, this driver is not enabled on Debian packaged kernels.

CVE-2019-10220

Various developers and researchers found that if a crafted file-system or malicious file server presented a directory with filenames including a '/' character, this could confuse and possibly defeat security checks in applications that read the directory.

The kernel will now return an error when reading such a directory, rather than passing the invalid filenames on to user-space.

CVE-2019-14895, CVE-2019-14901 ADLab of Venustech discovered potential heap buffer overflows in the mwifiex wifi driver. On systems using this driver, a malicious Wireless Access Point or adhoc/P2P peer could use these to cause a denial of service (memory corruption or crash) or possibly for remote code execution.

CVE-2019-14896, CVE-2019-14897 ADLab of Venustech discovered potential heap and stack buffer overflows in the libertas wifi driver. On systems using this driver, a malicious Wireless Access Point or adhoc/P2P peer could use these to cause a denial of service (memory corruption or crash) or possibly for remote code execution.

CVE-2019-15098

Hui Peng and Mathias Payer reported that the ath6kl wifi driver did not properly validate USB descriptors, which could lead to a null pointer dereference. An attacker able to add USB devices could use this to cause a denial of service (BUG/oops).

CVE-2019-15217

The syzkaller tool discovered that the zr364xx mdia driver did not correctly handle devices without a product name string, which could lead to a null pointer dereference. An attacker able to add USB devices could use this to cause a denial of service (BUG/oops).

CVE-2019-15291

The syzkaller tool discovered that the b2c2-flexcop-usb media driver did not properly validate USB descriptors, which could lead to a null pointer dereference. An attacker able to add USB devices could use this to cause a denial of service (BUG/oops).

CVE-2019-15505

The syzkaller tool discovered that the technisat-usb2 media driver did not properly validate incoming IR packets, which could lead to a heap buffer over-read. An attacker able to add USB devices could use this to cause a denial of service (BUG/oops) or to read sensitive information from kernel memory.

CVE-2019-16746

It was discovered that the wifi stack did not validate the content of beacon heads provided by user-space for use on a wifi interface in Access Point mode, which could lead to a heap buffer overflow. A local user permitted to configure a wifi ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);