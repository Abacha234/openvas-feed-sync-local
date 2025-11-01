# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705249");
  script_cve_id("CVE-2022-40617");
  script_tag(name:"creation_date", value:"2022-10-08 01:00:06 +0000 (Sat, 08 Oct 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-01 14:12:00 +0000 (Tue, 01 Nov 2022)");

  script_name("Debian: Security Advisory (DSA-5249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5249");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5249");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/strongswan");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-5249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lahav Schlesinger discovered a vulnerability in the revocation plugin of strongSwan, an IKE/IPsec suite.

The revocation plugin uses OCSP URIs and CRL distribution points (CDP) which come from certificates provided by the remote endpoint. The plugin didn't check for the certificate chain of trust before using those URIs, so an attacker could provided a crafted certificate containing URIs pointing to servers under their control, potentially leading to denial-of-service attacks.

For the stable distribution (bullseye), this problem has been fixed in version 5.9.1-1+deb11u3.

We recommend that you upgrade your strongswan packages.

For the detailed security status of strongswan please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);