# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03545.1");
  script_cve_id("CVE-2014-3499", "CVE-2014-5277", "CVE-2014-6407", "CVE-2014-6408", "CVE-2014-8178", "CVE-2014-8179", "CVE-2014-9356", "CVE-2014-9357", "CVE-2014-9358", "CVE-2015-3627", "CVE-2015-3629", "CVE-2015-3630", "CVE-2015-3631", "CVE-2016-3697", "CVE-2016-8867", "CVE-2016-9962", "CVE-2017-14992", "CVE-2017-16539", "CVE-2018-10892", "CVE-2018-15664", "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2018-20699", "CVE-2019-13509", "CVE-2019-14271", "CVE-2020-12912", "CVE-2020-13401", "CVE-2020-15257", "CVE-2020-8694", "CVE-2020-8695", "CVE-2021-21284", "CVE-2021-21285", "CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092", "CVE-2021-41103", "CVE-2021-41190", "CVE-2021-43565", "CVE-2022-24769", "CVE-2022-27191", "CVE-2022-36109", "CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842", "CVE-2024-23650", "CVE-2024-23651", "CVE-2024-23652", "CVE-2024-23653", "CVE-2024-29018", "CVE-2024-41110", "CVE-2025-22868", "CVE-2025-22869");
  script_tag(name:"creation_date", value:"2025-10-14 14:40:54 +0000 (Tue, 14 Oct 2025)");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:44:46 +0000 (Fri, 09 Feb 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03545-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503545-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999582");
  script_xref(name:"URL", value:"https://github.com/docker/buildx/releases/tag/v0.25.0");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-October/022860.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-stable' package(s) announced via the SUSE-SU-2025:03545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker-stable fixes the following issues:

Note this update contains a already fixed references mostly.

- Remove git-core recommends on SLE to avoid pulling it in unnecessary. (bsc#1250508)

 This feature is mostly intended for developers ('docker build git://') so
 most users already have the dependency installed, and the error when git is
 missing is fairly straightforward (so they can easily figure out what they
 need to install).

- Include historical changelog data from before the docker-stable fork. The
 initial changelog entry did technically provide all the necessary
 information, but our CVE tracking tools do not understand how the package is
 forked and so it seems that this package does not include fixes for ~12 years
 of updates. So, include a copy of the original package's changelog up until
 the fork point. bsc#1250596

- Update to docker-buildx v0.25.0. Upstream changelog:
 <[link moved to references]>

- Update to Go 1.23 for building now that upstream has switched their 23.0.x
 LTSS to use Go 1.23.

- Do not try to inject SUSEConnect secrets when in Rootless Docker mode, as
 Docker does not have permission to access the host zypper credentials in this
 mode (and unprivileged users cannot disable the feature using
 /etc/docker/suse-secrets-enable.) bsc#1240150

- Initial docker-stable fork, forked from Docker 24.0.7-ce release
 (packaged on 2024-02-14). The original changelog is included below for
 historical reference.");

  script_tag(name:"affected", value:"'docker-stable' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"docker-stable", rpm:"docker-stable~24.0.9_ce~150000.1.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-bash-completion", rpm:"docker-stable-bash-completion~24.0.9_ce~150000.1.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-fish-completion", rpm:"docker-stable-fish-completion~24.0.9_ce~150000.1.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-rootless-extras", rpm:"docker-stable-rootless-extras~24.0.9_ce~150000.1.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-stable-zsh-completion", rpm:"docker-stable-zsh-completion~24.0.9_ce~150000.1.25.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
