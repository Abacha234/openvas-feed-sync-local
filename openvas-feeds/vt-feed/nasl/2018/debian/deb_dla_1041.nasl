# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891041");
  script_cve_id("CVE-2017-10686", "CVE-2017-11111");
  script_tag(name:"creation_date", value:"2018-02-07 23:00:00 +0000 (Wed, 07 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-28 05:29:00 +0000 (Thu, 28 Mar 2019)");

  script_name("Debian: Security Advisory (DLA-1041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1041");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1041");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nasm' package(s) announced via the DLA-1041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-10686

In Netwide Assembler (NASM) 2.14rc0, there are multiple heap use after free vulnerabilities in the tool nasm. The related heap is allocated in the token() function and freed in the detoken() function (called by pp_getline()) - it is used again at multiple positions later that could cause multiple damages. For example, it causes a corrupted double-linked list in detoken(), a double free or corruption in delete_Token(), and an out-of-bounds write in detoken(). It has a high possibility to lead to a remote code execution attack.

CVE-2017-11111

In Netwide Assembler (NASM) 2.14rc0, preproc.c allows remote attackers to cause a denial of service (heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted file.

For Debian 7 Wheezy, these problems have been fixed in version 2.10.01-1+deb7u1.

We recommend that you upgrade your nasm packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nasm' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);