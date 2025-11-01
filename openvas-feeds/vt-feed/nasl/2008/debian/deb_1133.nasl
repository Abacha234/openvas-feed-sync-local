# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57202");
  script_cve_id("CVE-2006-0664", "CVE-2006-0665", "CVE-2006-0841", "CVE-2006-1577");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1133)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1133");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1133");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mantis' package(s) announced via the DSA-1133 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Mantis bug tracking system, which may lead to the execution of arbitrary web script. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-0664

A cross-site scripting vulnerability was discovered in config_defaults_inc.php.

CVE-2006-0665

Cross-site scripting vulnerabilities were discovered in query_store.php and manage_proj_create.php.

CVE-2006-0841

Multiple cross-site scripting vulnerabilities were discovered in view_all_set.php, manage_user_page.php, view_filters_page.php and proj_doc_delete.php.

CVE-2006-1577

Multiple cross-site scripting vulnerabilities were discovered in view_all_set.php.

For the stable distribution (sarge) these problems have been fixed in version 0.19.2-5sarge4.1.

For the unstable distribution (sid) these problems have been fixed in version 0.19.4-3.1.

We recommend that you upgrade your mantis package.");

  script_tag(name:"affected", value:"'mantis' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);