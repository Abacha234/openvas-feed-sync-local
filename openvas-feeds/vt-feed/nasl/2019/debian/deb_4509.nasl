# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704509");
  script_cve_id("CVE-2019-10081", "CVE-2019-10082", "CVE-2019-10092", "CVE-2019-10098", "CVE-2019-9517");
  script_tag(name:"creation_date", value:"2019-08-27 02:00:12 +0000 (Tue, 27 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-4509)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4509");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4509");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apache2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-4509 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2019-9517

Jonathan Looney reported that a malicious client could perform a denial of service attack (exhausting h2 workers) by flooding a connection with requests and basically never reading responses on the TCP connection.

CVE-2019-10081

Craig Young reported that HTTP/2 PUSHes could lead to an overwrite of memory in the pushing request's pool, leading to crashes.

CVE-2019-10082

Craig Young reported that the HTTP/2 session handling could be made to read memory after being freed, during connection shutdown.

CVE-2019-10092

Matei Mal Badanoiu reported a limited cross-site scripting vulnerability in the mod_proxy error page.

CVE-2019-10097

Daniel McCarney reported that when mod_remoteip was configured to use a trusted intermediary proxy server using the PROXY protocol, a specially crafted PROXY header could trigger a stack buffer overflow or NULL pointer deference. This vulnerability could only be triggered by a trusted proxy and not by untrusted HTTP clients. The issue does not affect the stretch release.

CVE-2019-10098

Yukitsugu Sasaki reported a potential open redirect vulnerability in the mod_rewrite module.

For the oldstable distribution (stretch), these problems have been fixed in version 2.4.25-3+deb9u8.

For the stable distribution (buster), these problems have been fixed in version 2.4.38-3+deb10u1.

We recommend that you upgrade your apache2 packages.

For the detailed security status of apache2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);