# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702876");
  script_cve_id("CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476");
  script_tag(name:"creation_date", value:"2014-03-11 23:00:00 +0000 (Tue, 11 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2876)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2876");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2876");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-2876 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer of the Red Hat Product Security Team discovered multiple vulnerabilities in the pdftoopvp CUPS filter, which could result in the execution of arbitrary code if a malformed PDF file is processed.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.4.4-7+squeeze4.

For the stable distribution (wheezy) and the unstable distribution (sid) the filter is now part of the cups-filters source package.

We recommend that you upgrade your cups packages.");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
