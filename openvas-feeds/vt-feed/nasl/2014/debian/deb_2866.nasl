# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702866");
  script_cve_id("CVE-2014-1959");
  script_tag(name:"creation_date", value:"2014-02-21 23:00:00 +0000 (Fri, 21 Feb 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2866)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2866");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2866");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls26' package(s) announced via the DSA-2866 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Suman Jana reported that GnuTLS, deviating from the documented behavior, considers a version 1 intermediate certificate as a CA certificate by default.

The oldstable distribution (squeeze) is not affected by this problem as X.509 version 1 trusted CA certificates are not allowed by default.

For the stable distribution (wheezy), this problem has been fixed in version 2.12.20-8.

For the testing distribution (jessie) and the unstable distribution (sid), this problem has been fixed in version 2.12.23-12.

We recommend that you upgrade your gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);