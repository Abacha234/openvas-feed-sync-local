# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705286");
  script_cve_id("CVE-2022-42898");
  script_tag(name:"creation_date", value:"2022-11-20 02:00:04 +0000 (Sun, 20 Nov 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 20:28:00 +0000 (Thu, 05 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-5286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5286");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5286");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/krb5");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-5286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Greg Hudson discovered integer overflow flaws in the PAC parsing in krb5, the MIT implementation of Kerberos, which may result in remote code execution (in a KDC, kadmin, or GSS or Kerberos application server process), information exposure (to a cross-realm KDC acting maliciously), or denial of service (KDC or kadmind process crash).

For the stable distribution (bullseye), this problem has been fixed in version 1.18.3-6+deb11u3.

We recommend that you upgrade your krb5 packages.

For the detailed security status of krb5 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);