# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703010");
  script_cve_id("CVE-2014-0480", "CVE-2014-0481", "CVE-2014-0482", "CVE-2014-0483");
  script_tag(name:"creation_date", value:"2014-08-21 22:00:00 +0000 (Thu, 21 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3010");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3010");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-3010 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Django, a high-level Python web development framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-0480

Florian Apolloner discovered that in certain situations, URL reversing could generate scheme-relative URLs which could unexpectedly redirect a user to a different host, leading to phishing attacks.

CVE-2014-0481

David Wilson reported a file upload denial of service vulnerability. Django's file upload handling in its default configuration may degrade to producing a huge number of `os.stat()` system calls when a duplicate filename is uploaded. A remote attacker with the ability to upload files can cause poor performance in the upload handler, eventually causing it to become very slow.

CVE-2014-0482

David Greisen discovered that under some circumstances, the use of the RemoteUserMiddleware middleware and the RemoteUserBackend authentication backend could result in one user receiving another user's session, if a change to the REMOTE_USER header occurred without corresponding logout/login actions.

CVE-2014-0483

Collin Anderson discovered that it is possible to reveal any field's data by modifying the popup and to_field parameters of the query string on an admin change form page. A user with access to the admin interface, and with sufficient knowledge of model structure and the appropriate URLs, could construct popup views which would display the values of non-relationship fields, including fields the application developer had not intended to expose in such a fashion.

For the stable distribution (wheezy), these problems have been fixed in version 1.4.5-1+deb7u8.

For the unstable distribution (sid), these problems have been fixed in version 1.6.6-1.

We recommend that you upgrade your python-django packages.");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);