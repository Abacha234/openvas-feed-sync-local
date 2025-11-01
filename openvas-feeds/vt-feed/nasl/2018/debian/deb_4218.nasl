# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704218");
  script_cve_id("CVE-2017-9951", "CVE-2018-1000115", "CVE-2018-1000127");
  script_tag(name:"creation_date", value:"2018-06-05 22:00:00 +0000 (Tue, 05 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4218)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4218");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4218");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/memcached");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'memcached' package(s) announced via the DSA-4218 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in memcached, a high-performance memory object caching system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2017-9951

Daniel Shapira reported a heap-based buffer over-read in memcached (resulting from an incomplete fix for CVE-2016-8705) triggered by specially crafted requests to add/set a key and allowing a remote attacker to cause a denial of service.

CVE-2018-1000115

It was reported that memcached listens to UDP by default. A remote attacker can take advantage of it to use the memcached service as a DDoS amplifier.

Default installations of memcached in Debian are not affected by this issue as the installation defaults to listen only on localhost. This update disables the UDP port by default. Listening on the UDP can be re-enabled in the /etc/memcached.conf (cf. /usr/share/doc/memcached/NEWS.Debian.gz).

CVE-2018-1000127

An integer overflow was reported in memcached, resulting in resource leaks, data corruption, deadlocks or crashes.

For the oldstable distribution (jessie), these problems have been fixed in version 1.4.21-1.1+deb8u2.

For the stable distribution (stretch), these problems have been fixed in version 1.4.33-1+deb9u1.

We recommend that you upgrade your memcached packages.

For the detailed security status of memcached please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'memcached' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);