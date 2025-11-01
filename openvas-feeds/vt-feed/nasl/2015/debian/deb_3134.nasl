# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703134");
  script_cve_id("CVE-2015-1306");
  script_tag(name:"creation_date", value:"2015-01-19 23:00:00 +0000 (Mon, 19 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3134)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3134");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3134");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sympa' package(s) announced via the DSA-3134 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the web interface of sympa, a mailing list manager. An attacker could take advantage of this flaw in the newsletter posting area, which allows sending to a list, or to oneself, any file located on the server filesystem and readable by the sympa user.

For the stable distribution (wheezy), this problem has been fixed in version 6.1.11~dfsg-5+deb7u2.

For the upcoming stable distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 6.1.23~dfsg-2.

We recommend that you upgrade your sympa packages.");

  script_tag(name:"affected", value:"'sympa' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);