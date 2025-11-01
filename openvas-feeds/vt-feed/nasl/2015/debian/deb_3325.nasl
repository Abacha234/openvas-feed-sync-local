# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703325");
  script_cve_id("CVE-2015-3183", "CVE-2015-3185");
  script_tag(name:"creation_date", value:"2015-07-31 22:00:00 +0000 (Fri, 31 Jul 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3325)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3325");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3325");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-3325 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2015-3183

An HTTP request smuggling attack was possible due to a bug in parsing of chunked requests. A malicious client could force the server to misinterpret the request length, allowing cache poisoning or credential hijacking if an intermediary proxy is in use.

CVE-2015-3185

A design error in the ap_some_auth_required function renders the API unusable in apache2 2.4.x. This could lead to modules using this API to allow access when they should otherwise not do so. The fix backports the new ap_some_authn_required API from 2.4.16. This issue does not affect the oldstable distribution (wheezy).

In addition, the updated package for the oldstable distribution (wheezy) removes a limitation of the Diffie-Hellman (DH) parameters to 1024 bits. This limitation may potentially allow an attacker with very large computing resources, like a nation-state, to break DH key exchange by precomputation. The updated apache2 package also allows to configure custom DH parameters. More information is contained in the changelog.Debian.gz file. These improvements were already present in the stable, testing, and unstable distributions.

For the oldstable distribution (wheezy), these problems have been fixed in version 2.2.22-13+deb7u5.

For the stable distribution (jessie), these problems have been fixed in version 2.4.10-10+deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);