# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703786");
  script_cve_id("CVE-2017-5953");
  script_tag(name:"creation_date", value:"2017-02-12 23:00:00 +0000 (Sun, 12 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-11 20:29:00 +0000 (Tue, 11 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-3786)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3786");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3786");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vim' package(s) announced via the DSA-3786 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Editor spell files passed to the vim (Vi IMproved) editor may result in an integer overflow in memory allocation and a resulting buffer overflow which potentially could result in the execution of arbitrary code or denial of service.

For the stable distribution (jessie), this problem has been fixed in version 2:7.4.488-7+deb8u2.

For the unstable distribution (sid), this problem has been fixed in version 2:8.0.0197-2.

We recommend that you upgrade your vim packages.");

  script_tag(name:"affected", value:"'vim' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);