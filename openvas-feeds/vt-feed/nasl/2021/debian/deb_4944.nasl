# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704944");
  script_cve_id("CVE-2021-36222");
  script_tag(name:"creation_date", value:"2021-07-26 03:00:13 +0000 (Mon, 26 Jul 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-02 19:14:00 +0000 (Mon, 02 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-4944)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4944");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4944");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/krb5");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-4944 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Key Distribution Center (KDC) in krb5, the MIT implementation of Kerberos, is prone to a NULL pointer dereference flaw. An unauthenticated attacker can take advantage of this flaw to cause a denial of service (KDC crash) by sending a request containing a PA-ENCRYPTED-CHALLENGE padata element without using FAST.

For the stable distribution (buster), this problem has been fixed in version 1.17-3+deb10u2.

We recommend that you upgrade your krb5 packages.

For the detailed security status of krb5 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);