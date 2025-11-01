# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703761");
  script_cve_id("CVE-2016-9877");
  script_tag(name:"creation_date", value:"2017-01-12 23:00:00 +0000 (Thu, 12 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-21 10:29:00 +0000 (Fri, 21 Sep 2018)");

  script_name("Debian: Security Advisory (DSA-3761)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3761");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3761");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rabbitmq-server' package(s) announced via the DSA-3761 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that RabbitMQ, an implementation of the AMQP protocol, didn't correctly validate MQTT (MQ Telemetry Transport) connection authentication. This allowed anyone to login to an existing user account without having to provide a password.

For the stable distribution (jessie), this problem has been fixed in version 3.3.5-1.1+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this problem has been fixed in version 3.6.6-1.

We recommend that you upgrade your rabbitmq-server packages.");

  script_tag(name:"affected", value:"'rabbitmq-server' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);