# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843264");
  script_cve_id("CVE-2016-9877");
  script_tag(name:"creation_date", value:"2017-08-01 04:53:13 +0000 (Tue, 01 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-21 10:29:00 +0000 (Fri, 21 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-3374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3374-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3374-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rabbitmq-server' package(s) announced via the USN-3374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that RabbitMQ incorrectly handled MQTT (MQ Telemetry
Transport) authentication. A remote attacker could use this issue to
authenticate successfully with an existing username by omitting the
password.");

  script_tag(name:"affected", value:"'rabbitmq-server' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
