# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704762");
  script_cve_id("CVE-2020-24660");
  script_tag(name:"creation_date", value:"2020-09-10 07:28:26 +0000 (Thu, 10 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 19:42:00 +0000 (Fri, 18 Sep 2020)");

  script_name("Debian: Security Advisory (DSA-4762)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4762");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4762");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lemonldap-ng");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lemonldap-ng' package(s) announced via the DSA-4762 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the default configuration files for running the Lemonldap::NG Web SSO system on the Nginx web server were susceptible to authorisation bypass of URL access rules. The Debian packages do not use Nginx by default.

For the stable distribution (buster), this problem has been fixed in version 2.0.2+ds-7+deb10u5, this update provides fixed example configuration which needs to be integrated into Lemonldap::NG deployments based on Nginx.

We recommend that you upgrade your lemonldap-ng packages.

For the detailed security status of lemonldap-ng please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'lemonldap-ng' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);