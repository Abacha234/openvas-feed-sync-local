# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703722");
  script_cve_id("CVE-2016-1248");
  script_tag(name:"creation_date", value:"2016-11-21 23:00:00 +0000 (Mon, 21 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3722)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3722");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3722");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vim' package(s) announced via the DSA-3722 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Larysch and Bram Moolenaar discovered that vim, an enhanced vi editor, does not properly validate values for the filetype, syntax and keymap options, which may result in the execution of arbitrary code if a file with a specially crafted modeline is opened.

For the stable distribution (jessie), this problem has been fixed in version 2:7.4.488-7+deb8u1.

We recommend that you upgrade your vim packages.");

  script_tag(name:"affected", value:"'vim' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);