# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702897");
  script_cve_id("CVE-2012-3544", "CVE-2013-2067", "CVE-2013-2071", "CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0050");
  script_tag(name:"creation_date", value:"2014-04-07 22:00:00 +0000 (Mon, 07 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2897)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2897");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2897");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat7' package(s) announced via the DSA-2897 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in the Tomcat servlet and JSP engine:

CVE-2013-2067

FORM authentication associates the most recent request requiring authentication with the current session. By repeatedly sending a request for an authenticated resource while the victim is completing the login form, an attacker could inject a request that would be executed using the victim's credentials.

CVE-2013-2071

A runtime exception in AsyncListener.onComplete() prevents the request from being recycled. This may expose elements of a previous request to a current request.

CVE-2013-4286

Reject requests with multiple content-length headers or with a content-length header when chunked encoding is being used.

CVE-2013-4322

When processing a request submitted using the chunked transfer encoding, Tomcat ignored but did not limit any extensions that were included. This allows a client to perform a limited denial of service by streaming an unlimited amount of data to the server.

CVE-2014-0050

Multipart requests with a malformed Content-Type header could trigger an infinite loop causing a denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 7.0.28-4+deb7u1.

For the testing distribution (jessie), these problems have been fixed in version 7.0.52-1.

For the unstable distribution (sid), these problems have been fixed in version 7.0.52-1.

We recommend that you upgrade your tomcat7 packages.");

  script_tag(name:"affected", value:"'tomcat7' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);