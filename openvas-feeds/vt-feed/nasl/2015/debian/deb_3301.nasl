# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703301");
  script_cve_id("CVE-2015-3281");
  script_tag(name:"creation_date", value:"2015-07-04 22:00:00 +0000 (Sat, 04 Jul 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3301");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3301");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'haproxy' package(s) announced via the DSA-3301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Charlie Smurthwaite of aTech Media discovered a flaw in HAProxy, a fast and reliable load balancing reverse proxy, when HTTP pipelining is used. A client can take advantage of this flaw to cause data corruption and retrieve uninitialized memory contents that exhibit data from a past request or session.

For the stable distribution (jessie), this problem has been fixed in version 1.5.8-3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1.5.14-1.

We recommend that you upgrade your haproxy packages.");

  script_tag(name:"affected", value:"'haproxy' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);