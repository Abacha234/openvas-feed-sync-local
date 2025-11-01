# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844350");
  script_cve_id("CVE-2019-12528", "CVE-2020-8449", "CVE-2020-8450", "CVE-2020-8517");
  script_tag(name:"creation_date", value:"2020-02-21 04:00:18 +0000 (Fri, 21 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 20:47:00 +0000 (Thu, 04 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4289-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4289-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid, squid3' package(s) announced via the USN-4289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeriko One discovered that Squid incorrectly handled memory when connected
to an FTP server. A remote attacker could possibly use this issue to obtain
sensitive information from Squid memory. (CVE-2019-12528)

Regis Leroy discovered that Squid incorrectly handled certain HTTP
requests. A remote attacker could possibly use this issue to access server
resources prohibited by earlier security filters. (CVE-2020-8449)

Guido Vranken discovered that Squid incorrectly handled certain buffer
operations when acting as a reverse proxy. A remote attacker could use
this issue to cause Squid to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2020-8450)

Aaron Costello discovered that Squid incorrectly handled certain NTLM
authentication credentials. A remote attacker could possibly use this issue
to cause Squid to crash, resulting in a denial of service. (CVE-2020-8517)");

  script_tag(name:"affected", value:"'squid, squid3' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
