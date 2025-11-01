# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703796");
  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743");
  script_tag(name:"creation_date", value:"2017-02-25 23:00:00 +0000 (Sat, 25 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:39:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-3796)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3796");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3796");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sitesummary' package(s) announced via the DSA-3796 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Apache2 HTTP server.

CVE-2016-0736

RedTeam Pentesting GmbH discovered that mod_session_crypto was vulnerable to padding oracle attacks, which could allow an attacker to guess the session cookie.

CVE-2016-2161

Maksim Malyutin discovered that malicious input to mod_auth_digest could cause the server to crash, causing a denial of service.

CVE-2016-8743

David Dennerline, of IBM Security's X-Force Researchers, and Regis Leroy discovered problems in the way Apache handled a broad pattern of unusual whitespace patterns in HTTP requests. In some configurations, this could lead to response splitting or cache pollution vulnerabilities. To fix these issues, this update makes Apache httpd be more strict in what HTTP requests it accepts.

If this causes problems with non-conforming clients, some checks can be relaxed by adding the new directive HttpProtocolOptions unsafe to the configuration.

This update also fixes the issue where mod_reqtimeout was not enabled by default on new installations.

For the stable distribution (jessie), these problems have been fixed in version 2.4.10-10+deb8u8.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 2.4.25-1.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'sitesummary' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);