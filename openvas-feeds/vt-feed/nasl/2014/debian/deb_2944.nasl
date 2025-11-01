# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702944");
  script_cve_id("CVE-2014-3466");
  script_tag(name:"creation_date", value:"2014-05-31 22:00:00 +0000 (Sat, 31 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2944)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2944");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2944");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls26' package(s) announced via the DSA-2944 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joonas Kuorilehto discovered that GNU TLS performed insufficient validation of session IDs during TLS/SSL handshakes. A malicious server could use this to execute arbitrary code or perform denial of service.

For the stable distribution (wheezy), this problem has been fixed in version 2.12.20-8+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 2.12.23-16.

We recommend that you upgrade your gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);