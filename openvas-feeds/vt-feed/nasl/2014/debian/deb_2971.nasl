# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702971");
  script_cve_id("CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533");
  script_tag(name:"creation_date", value:"2014-07-01 22:00:00 +0000 (Tue, 01 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2971)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2971");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2971");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dbus' package(s) announced via the DSA-2971 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in dbus, an asynchronous inter-process communication system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-3477

Alban Crequy at Collabora Ltd. discovered that dbus-daemon sends an AccessDenied error to the service instead of a client when the client is prohibited from accessing the service. A local attacker could use this flaw to cause a bus-activated service that is not currently running to attempt to start, and fail, denying other users access to this service.

CVE-2014-3532

Alban Crequy at Collabora Ltd. discovered a bug in dbus-daemon's support for file descriptor passing. A malicious process could force system services or user applications to be disconnected from the D-Bus system by sending them a message containing a file descriptor, leading to a denial of service.

CVE-2014-3533

Alban Crequy at Collabora Ltd. and Alejandro Martinez Suarez discovered that a malicious process could force services to be disconnected from the D-Bus system by causing dbus-daemon to attempt to forward invalid file descriptors to a victim process, leading to a denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 1.6.8-1+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 1.8.6-1.

We recommend that you upgrade your dbus packages.");

  script_tag(name:"affected", value:"'dbus' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);