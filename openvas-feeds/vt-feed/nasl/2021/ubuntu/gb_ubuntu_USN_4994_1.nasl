# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844982");
  script_cve_id("CVE-2020-13950", "CVE-2020-35452", "CVE-2021-26690", "CVE-2021-26691", "CVE-2021-30641");
  script_tag(name:"creation_date", value:"2021-06-22 03:01:29 +0000 (Tue, 22 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4994-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4994-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4994-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-4994-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marc Stern discovered that the Apache mod_proxy_http module incorrectly
handled certain requests. A remote attacker could possibly use this issue
to cause Apache to crash, resulting in a denial of service. This issue only
affected Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2020-13950)

Antonio Morales discovered that the Apache mod_auth_digest module
incorrectly handled certain Digest nonces. A remote attacker could possibly
use this issue to cause Apache to crash, resulting in a denial of service.
(CVE-2020-35452)

Antonio Morales discovered that the Apache mod_session module incorrectly
handled certain Cookie headers. A remote attacker could possibly use this
issue to cause Apache to crash, resulting in a denial of service.
(CVE-2021-26690)

Christophe Jaillet discovered that the Apache mod_session module
incorrectly handled certain SessionHeader values. A remote attacker could
use this issue to cause Apache to crash, resulting in a denial of service,
or possibly execute arbitrary code. (CVE-2021-26691)

Christoph Anton Mitterer discovered that the new MergeSlashes configuration
option resulted in unexpected behaviour in certain situations.
(CVE-2021-30641)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
