# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702719");
  script_cve_id("CVE-2013-1788", "CVE-2013-1790");
  script_tag(name:"creation_date", value:"2013-07-09 22:00:00 +0000 (Tue, 09 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2719)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2719");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2719");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'poppler' package(s) announced via the DSA-2719 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the poppler PDF rendering library.

CVE-2013-1788

Multiple invalid memory access issues, which could potentially lead to arbitrary code execution if the user were tricked into opening a malformed PDF document.

CVE-2013-1790

An uninitialized memory issue, which could potentially lead to arbitrary code execution if the user were tricked into opening a malformed PDF document.

For the oldstable distribution (squeeze), these problems have been fixed in version 0.12.4-1.2+squeeze3.

For the stable (wheezy), testing (jessie), and unstable (sid) distributions, these problems have been fixed in version 0.18.4-6.

We recommend that you upgrade your poppler packages.");

  script_tag(name:"affected", value:"'poppler' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);