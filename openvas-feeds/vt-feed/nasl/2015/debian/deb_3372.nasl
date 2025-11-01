# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703372");
  script_cve_id("CVE-2015-5257", "CVE-2015-7613");
  script_tag(name:"creation_date", value:"2015-10-12 22:00:00 +0000 (Mon, 12 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3372)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3372");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3372");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3372 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, unauthorised information disclosure or unauthorised information modification.

CVE-2015-2925

Jann Horn discovered that when a subdirectory of a filesystem was bind-mounted into a chroot or mount namespace, a user that should be confined to that chroot or namespace could access the whole of that filesystem if they had write permission on an ancestor of the subdirectory. This is not a common configuration for wheezy, and the issue has previously been fixed for jessie.

CVE-2015-5257

Moein Ghasemzadeh of Istuary Innovation Labs reported that a USB device could cause a denial of service (crash) by imitating a Whiteheat USB serial device but presenting a smaller number of endpoints.

CVE-2015-5283

Marcelo Ricardo Leitner discovered that creating multiple SCTP sockets at the same time could cause a denial of service (crash) if the sctp module had not previously been loaded. This issue only affects jessie.

CVE-2015-7613

Dmitry Vyukov discovered that System V IPC objects (message queues and shared memory segments) were made accessible before their ownership and other attributes were fully initialised. If a local user can race against another user or service creating a new IPC object, this may result in unauthorised information disclosure, unauthorised information modification, denial of service and/or privilege escalation.

A similar issue existed with System V semaphore arrays, but was less severe because they were always cleared before being fully initialised.

For the oldstable distribution (wheezy), these problems have been fixed in version 3.2.68-1+deb7u5.

For the stable distribution (jessie), these problems have been fixed in version 3.16.7-ckt11-1+deb8u5.

For the unstable distribution (sid), these problems have been fixed in version 4.2.3-1 or earlier versions.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);