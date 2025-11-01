# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704229");
  script_cve_id("CVE-2018-10811", "CVE-2018-5388");
  script_tag(name:"creation_date", value:"2018-06-13 22:00:00 +0000 (Wed, 13 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 14:28:00 +0000 (Tue, 18 May 2021)");

  script_name("Debian: Security Advisory (DSA-4229)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4229");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4229");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/strongswan");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-4229 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in strongSwan, an IKE/IPsec suite.

CVE-2018-5388

The stroke plugin did not verify the message length when reading from its control socket. This vulnerability could lead to denial of service. On Debian write access to the socket requires root permission on default configuration.

CVE-2018-10811

A missing variable initialization in IKEv2 key derivation could lead to a denial of service (crash of the charon IKE daemon) if the openssl plugin is used in FIPS mode and the negotiated PRF is HMAC-MD5.

For the oldstable distribution (jessie), these problems have been fixed in version 5.2.1-6+deb8u6.

For the stable distribution (stretch), these problems have been fixed in version 5.5.1-4+deb9u2.

We recommend that you upgrade your strongswan packages.

For the detailed security status of strongswan please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);