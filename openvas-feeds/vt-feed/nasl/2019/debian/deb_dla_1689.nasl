# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891689");
  script_cve_id("CVE-2017-7608", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149", "CVE-2019-7150", "CVE-2019-7665");
  script_tag(name:"creation_date", value:"2019-02-25 23:00:00 +0000 (Mon, 25 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 19:53:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-1689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1689");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1689");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'elfutils' package(s) announced via the DLA-1689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues in elfutils, a collection of utilities to handle ELF objects, have been found either by fuzzing or by using an AddressSanitizer.

CVE-2019-7665

Due to a heap-buffer-overflow problem in function elf32_xlatetom() a crafted ELF input can cause segmentation faults.

CVE-2019-7150

Add sanity check for partial core file dynamic data read.

CVE-2019-7149

Due to a heap-buffer-overflow problem in function read_srclines() a crafted ELF input can cause segmentation faults.

CVE-2018-18521

By using a crafted ELF file, containing a zero sh_entsize, a divide-by-zero vulnerability could allow remote attackers to cause a denial of service (application crash).

CVE-2018-18520

By fuzzing an Invalid Address Deference problem in function elf_end has been found.

CVE-2018-18310

By fuzzing an Invalid Address Read problem in eu-stack has been found.

CVE-2018-16062

By using an AddressSanitizer a heap-buffer-overflow has been found.

CVE-2017-7613

By using fuzzing it was found that an allocation failure was not handled properly.

CVE-2017-7612

By using a crafted ELF file, containing an invalid sh_entsize, remote attackers could cause a denial of service (application crash).

CVE-2017-7611

By using a crafted ELF file remote attackers could cause a denial of service (application crash).

CVE-2017-7610

By using a crafted ELF file remote attackers could cause a denial of service (application crash).

CVE-2017-7608

By fuzzing a heap based buffer overflow has been detected.

For Debian 8 'Jessie', these problems have been fixed in version 0.159-4.2+deb8u1.

We recommend that you upgrade your elfutils packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'elfutils' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);