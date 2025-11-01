# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71478");
  script_cve_id("CVE-2012-1118", "CVE-2012-1119", "CVE-2012-1120", "CVE-2012-1122", "CVE-2012-1123", "CVE-2012-2692");
  script_tag(name:"creation_date", value:"2012-08-10 07:06:58 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2500");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2500");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mantis' package(s) announced via the DSA-2500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Mantis, an issue tracking system.

CVE-2012-1118

Mantis installation in which the private_bug_view_threshold configuration option has been set to an array value do not properly enforce bug viewing restrictions.

CVE-2012-1119

Copy/clone bug report actions fail to leave an audit trail.

CVE-2012-1120

The delete_bug_threshold/bugnote_allow_user_edit_delete access check can be bypassed by users who have write access to the SOAP API.

CVE-2012-1122

Mantis performed access checks incorrectly when moving bugs between projects.

CVE-2012-1123

A SOAP client sending a null password field can authenticate as the Mantis administrator.

CVE-2012-2692

Mantis does not check the delete_attachments_threshold permission when a user attempts to delete an attachment from an issue.

For the stable distribution (squeeze), these problems have been fixed in version 1.1.8+dfsg-10squeeze2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 1.2.11-1.

We recommend that you upgrade your mantis packages.");

  script_tag(name:"affected", value:"'mantis' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);