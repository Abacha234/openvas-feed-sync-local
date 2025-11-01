# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705056");
  script_cve_id("CVE-2021-45079");
  script_tag(name:"creation_date", value:"2022-01-26 02:00:34 +0000 (Wed, 26 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 17:57:00 +0000 (Mon, 07 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5056)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5056");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5056");
  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2022/01/24/strongswan-vulnerability-");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/strongswan");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-5056 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhuowei Zhang discovered a bug in the EAP authentication client code of strongSwan, an IKE/IPsec suite, that may allow to bypass the client and in some scenarios even the server authentication, or could lead to a denial-of-service attack.

When using EAP authentication (RFC 3748), the successful completion of the authentication is indicated by an EAP-Success message sent by the server to the client. strongSwan's EAP client code handled early EAP-Success messages incorrectly, either crashing the IKE daemon or concluding the EAP method prematurely.

End result depend on the used configuration, more details can be found in upstream advisory at [link moved to references](cve-2021-45079).html

For the oldstable distribution (buster), this problem has been fixed in version 5.7.2-1+deb10u2.

For the stable distribution (bullseye), this problem has been fixed in version 5.9.1-1+deb11u2.

We recommend that you upgrade your strongswan packages.

For the detailed security status of strongswan please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);