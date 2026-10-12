# Antigravity 사용량 모니터링 및 캡 제어 (`agy-admin`)

[English](README.md) | [한국어](README.ko.md)

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](pyproject.toml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

`agy-admin`은 Gemini Enterprise 환경에서 동작하는 Google Antigravity(데스크톱, CLI, IDE 확장 프로그램)의 사용자별 사용량을 모니터링하고 쿼터 캡(Cap)을 관리하는 CLI 및 배치 도구입니다.

> **Disclaimer**: 이 프로젝트는 기업 환경의 모니터링 및 거버넌스 지원을 위해 작성된 커스텀 솔루션이며, Google Cloud의 공식 지원 제품이 아닙니다.

### 적용 범위 안내
이 도구는 대상 프로젝트에 직접 부여된 개별 `user:` IAM 바인딩만 제어할 수 있습니다. Google 그룹(`group:`), 도메인 바인딩(`domain:`), 상위 폴더/조직 상속, 또는 상위 권한 역할(`roles/owner`, `roles/discoveryengine.admin` 등)을 통해 접근 권한을 얻은 사용자는 개별 바인딩을 수정해도 실제 접근을 제한할 수 없습니다.

이 경우 `agy-admin`은 해당 사용자를 `NOT_ENFORCEABLE` 상태로 분류하고 IAM 변경을 건너뛴 뒤 **수동 조치 필요(Manual Action Required)** 항목으로 분리합니다.

도입 전 [`scripts/preflight_check.sh`](scripts/preflight_check.sh)를 실행하여 프로젝트 내 제어 가능한 사용자 비율을 확인하십시오. 자세한 내용은 [알려진 제약사항](#11-알려진-제약사항)을 참고하십시오.

> **v0.2.0 안내**: v0.2.0에는 상태 모델, 마커 역할, 설정 스키마에 대한 주요 변경 사항이 포함되어 있습니다. v0.1.0에서 업데이트하는 경우 [CHANGELOG.md](CHANGELOG.md)를 확인하고 `scripts/create_custom_role.sh`를 다시 실행하십시오.

---

## 목차

- [1. 주요 기능](#1-주요-기능)
- [2. 아키텍처 및 동작 원리](#2-아키텍처-및-동작-원리)
- [3. 사전 요구사항 및 설정](#3-사전-요구사항-및-설정)
- [4. 설치](#4-설치)
- [5. 사용자 온보딩 흐름](#5-사용자-온보딩-흐름)
- [6. CLI 사용 가이드 (`agy-admin-cli`)](#6-cli-사용-가이드-agy-admin-cli)
- [7. Cloud Run 배치 잡 (자동 집행)](#7-cloud-run-배치-잡-자동-집행)
- [8. 설정 및 환경 변수](#8-설정-및-환경-변수)
- [9. 테스트 실행](#9-테스트-실행)
- [10. 참고 문서](#10-참고-문서)
- [11. 알려진 제약사항](#11-알려진-제약사항)

---

## 1. 주요 기능

- **Cloud Logging 기반 사용량 분석**: `businessaicode.googleapis.com%2Finference_response` 로그에서 사용자별 요청 수, 토큰(총 토큰, 프롬프트, 생성 토큰), 클라이언트 종류, 모델 식별자를 파싱합니다.
- **다양한 집계 주기 및 윈도우**:
  - 기간: `daily`, `weekly`, `monthly`, `all`(최근 90일 제한)
  - 윈도우 계산 방식: `calendar`(UTC 00:00 기준) 또는 `rolling`(최근 24시간, 7일 등의 슬라이딩 윈도우)
- **안전한 캡 집행 규칙**:
  - 외부 데이터베이스 없이 동작합니다.
  - 자동 사이클은 제어 가능한 상태(`ENFORCEABLE_ALLOWED`)의 사용자만 차단하고, 도구가 차단했던 사용자(`CAPPED_BY_TOOL`)만 복구합니다.
- **집행 가능 여부 구분 및 수동 조치 안내**:
  - 도구가 직접 제어할 수 없는 위반자(그룹 멤버, 상위 권한 보유자 등)는 차단 성공으로 잘못 집계하지 않고 '수동 조치 필요'로 분류합니다.
  - 전체 대상 대비 실제 제어율(Coverage)을 산출하여 보고합니다.
- **안전 게이트(Safety Gates)**: IAM 정책을 수정하기 전에 정책 조회 성공 여부, 사용자 상태 판정 가능 여부, 로그 데이터 유효성, 변경량 서킷 브레이커, 그룹 권한 유무 등 5가지 항목을 사전 검증합니다.
- **수동 차단과 자동 차단 분리**: 관리자가 직접 비활성화한 계정(`disallow`)과 캡 초과로 차단된 계정을 별도 마커 역할로 구분하여, 오프보딩된 계정이 배치 사이클에 의해 자동으로 복구되지 않도록 방지합니다.
- **Resource Manager SDK 연동**: `google.cloud.resourcemanager_v3`를 사용하여 IAM 정책 버전 3을 준수하며, 한 사이클의 변경 사항을 단일 read-modify-write 배치로 처리합니다.
- **다양한 출력 형식**: 터미널 컬러 테이블, 구조화된 JSON, CSV 파일 내보내기를 지원합니다.
- **웹훅 알림**: 캡 차단, 복구, 사이클 중단, 수동 조치 필요 항목 발생 시 Slack 또는 Google Chat 웹훅으로 알림을 전송합니다.
- **관리 감사 로그**: 관리자 작업 및 주요 상태 변경 내역을 Cloud Logging(`projects/{PROJECT_ID}/logs/agy-admin%2Fadmin_actions`)에 구조화된 로그로 기록합니다.

---

## 2. 아키텍처 및 동작 원리

### 1) 관측(Observability) 파이프라인
Gemini Enterprise 환경에서 Antigravity 추론 요청은 Business AI Code 백엔드(`businessaicode.googleapis.com`)를 경유합니다. 텔레메트리 로그는 고객 GCP 프로젝트의 Cloud Logging으로 전달됩니다.
- **로그 스트림 이름**: `projects/{PROJECT_ID}/logs/businessaicode.googleapis.com%2Finference_response`
- **주요 필드**:
  - `labels.user_id`: 인증된 사용자 이메일 (예: `user@company.com`)
  - `labels.client_name`: 호출한 클라이언트 도구 (`antigravity_hub`, `antigravity_cli`, IDE 플러그인 등)
  - `labels.model_id`: 사용 모델 식별자 (`labels.model`도 fallback으로 지원)
  - `jsonPayload.metadata.totalTokenCount`: 요청당 총 토큰 수

### 2) IAM 평가 모델 (6개 상태)

`agy-admin`은 단순히 특정 역할의 보유 여부만 확인하지 않고, 개별 바인딩을 통해 해당 사용자의 권한을 안전하게 추가/제거할 수 있는 상태인지 검증한 뒤 작업을 수행합니다.

| 상태 | 설명 | 자동 차단 | 자동 복구 |
|---|---|:---:|:---:|
| `ENFORCEABLE_ALLOWED` | 기본 역할(`roles/discoveryengine.agentspaceUser`)이 개별 `user:` 바인딩으로만 부여된 상태 | 가능 | - |
| `CAPPED_BY_TOOL` | 캡 초과로 도구에 의해 일시 제한된 상태 (`CustomAntigravityCapBlocked` 보유) | - | 가능 |
| `BLOCKED_BY_ADMIN` | 관리자가 수동으로 차단한 상태 (`CustomAntigravityAdminBlocked` 또는 v0.1.0 레거시 역할 보유) | - | 불가 |
| `NOT_ENFORCEABLE` | 접근 권한은 있으나 사용자 단위로 회수할 수 없는 상태 (그룹, 상속, 관리자 역할 등) | 불가 | 불가 |
| `NO_ACCESS` | 활성화된 접근 경로가 없는 상태 | 불가 | 불가 |
| `UNKNOWN` | 정책 조회 실패 등으로 상태를 판정할 수 없는 상태 | 불가 | 불가 |

`NOT_ENFORCEABLE` 상태는 사유 코드(`PRIVILEGED_ROLE`, `OTHER_ACCESS_ROLE`, `GROUP_GRANT_PRESENT`, `INHERITED_BINDING`, `CONFLICTING_BINDINGS`)를 포함합니다. `UNKNOWN` 상태는 `POLICY_UNREADABLE` 또는 `ANCESTOR_UNCHECKED`를 포함합니다.

수동 `allow` 및 `disallow` 명령어는 `NOT_ENFORCEABLE` 및 `UNKNOWN` 상태의 계정에 대한 작업을 항상 거부하며, 이를 우회하는 옵션은 제공하지 않습니다. 개별 프로젝트 바인딩 외부에서 부여된 접근 권한은 이 도구가 회수할 수 없으므로, 해당 계정에 마커 역할을 부여하면 아무것도 제거하지 못한 채 권한만 추가되고 실제로 일어나지 않은 차단이 성공으로 기록됩니다. 이런 계정은 **수동 조치 필요(Manual Action Required)** 항목에 사유 코드별 조치 방법과 함께 표시되며, 명령어는 종료 코드 `2`를 반환합니다.

### 3) 마커 역할

사용량을 제한할 때 `agy-admin`은 `roles/discoveryengine.agentspaceUser`를 제거하고, `businessaicode.*` 권한만 제외한 커스텀 마커 역할을 부여합니다. 이를 통해 Antigravity 개발 도구 호출은 제한하되 일반 Gemini Enterprise 채팅 및 검색 권한은 유지합니다.

| 역할 ID | 부여 주체 | 자동 복구 여부 |
|---|---|---|
| `CustomAntigravityCapBlocked` | 캡 집행 배치 작업 / `cap apply` | 예 (사용량이 캡 이하로 내려가면 복구) |
| `CustomAntigravityAdminBlocked` | 관리자 수동 명령어 (`disallow`) | 아니오 (관리자 `allow` 전까지 유지) |
| `CustomAntigravityRestrictedUser` | v0.1.0 레거시 환경 | 아니오 (관리자 차단으로 간주) |

### 4) 안전 게이트

자동 집행 사이클은 IAM 정책을 수정하기 전에 다섯 가지 안전 게이트를 검증합니다.

| 게이트 | 조건 | 동작 |
|---|---|---|
| `G1_POLICY_READABLE` | 프로젝트 IAM 정책 조회 실패 | 사이클 중단 (exit code 3) |
| `G2_ANY_DETERMINATE` | 사용자 상태를 한 명도 판정할 수 없음 | 사이클 중단 (exit code 3) |
| `G3_TELEMETRY_HEALTHY` | 사용량 쿼리 실패 또는 결과 0건 | 차단은 적용하되, 자동 복구는 보류 |
| `G4_CHANGE_BUDGET` | 변경 대상이 `max(10, 전체 인원의 20%)` 초과 | 사이클 중단 (exit code 3) |
| `G5_NON_USER_GRANT_ABSENT` | 접근 역할에 그룹/도메인 바인딩 존재 | 경고 출력 및 해당 사용자 `NOT_ENFORCEABLE` 분류 |

게이트 G3는 로깅 파이프라인 장애나 설정 오류로 로그 조회가 비어 있을 때 차단된 사용자가 일괄 해제되는 오작동을 방지합니다.

---

## 3. 사전 요구사항 및 설정

### 1) 필수 IAM 역할
명령어를 실행하는 사용자 또는 Cloud Run 서비스 계정에 다음 역할이 필요합니다.
- `roles/logging.viewer`: Cloud Logging에서 추론 메트릭 조회
- `roles/logging.logWriter`: 관리 감사 로그 기록
- `roles/resourcemanager.projectIamAdmin`: 프로젝트 IAM 정책 바인딩 관리
- `roles/iam.roleViewer`: 커스텀 마커 역할 정의 조회
- `roles/iam.roleAdmin`: 커스텀 마커 역할 생성 (초기 1회만 필요)

### 2) Google Cloud CLI 인증
```bash
# gcloud 인증
gcloud auth login

# Application Default Credentials (ADC) 설정
gcloud auth application-default login

# 대상 프로젝트 설정
gcloud config set project <PROJECT_ID>
```

### 3) 필수 GCP API 활성화
```bash
gcloud services enable \
  businessaicode.googleapis.com \
  discoveryengine.googleapis.com \
  logging.googleapis.com \
  --project <PROJECT_ID>
```

### 4) Gemini Enterprise 관측 기능 활성화
사용자별 토큰 수 집계를 위해 Gemini Enterprise 콘솔에서 메타데이터 로깅을 활성화해야 합니다.
1. **Gemini Enterprise**(또는 Discovery Engine) > **Configurations**로 이동합니다.
2. **AI Developer Tools** 탭에서 **Enable AI Developer Tools**를 켭니다.
3. **Observability** 탭에서:
   - **Enable instrumentation of OpenTelemetry traces and logs**를 활성화합니다.
   - **Metadata Logging (`metadata_logging_enabled`)**을 활성화합니다.

Metadata Logging이 비활성화되면 사용량 로그가 수집되지 않습니다. 게이트 G3가 비정상적인 일괄 복구는 방지하지만 캡 위반도 감지할 수 없게 되므로, 운영 중에는 설정을 유지하십시오.

### 5) 사전 점검(Preflight) 실행
자동 집행을 활성화하기 전에 프로젝트의 IAM 구성이 개별 바인딩 제어 방식과 호환되는지 점검합니다.

```bash
chmod +x scripts/preflight_check.sh
./scripts/preflight_check.sh <PROJECT_ID>
```

점검 항목:
- `roles/discoveryengine.agentspaceUser` 역할에 할당된 그룹(`group:`), 도메인(`domain:`), `allUsers` 멤버
- 대상 역할에 설정된 조건부(Conditional) IAM 바인딩
- 관리자 및 상위 권한 역할을 보유한 개별 사용자
- 상위 폴더 또는 조직 단위에서 상속된 접근 권한

0이 아닌 코드로 종료되는 경우, 일부 사용자가 `NOT_ENFORCEABLE`로 분류됨을 의미합니다.

### 6) 커스텀 마커 역할 생성
```bash
chmod +x scripts/create_custom_role.sh
./scripts/create_custom_role.sh <PROJECT_ID>
```

`CustomAntigravityCapBlocked`와 `CustomAntigravityAdminBlocked` 두 역할을 생성합니다. 기존 v0.1.0 역할(`CustomAntigravityRestrictedUser`)이 감지되면 이관 안내가 출력됩니다.

---

## 4. 설치

```bash
# 가상환경 생성 및 활성화 (Python 3.10+)
python3 -m venv venv
source venv/bin/activate

# agy-admin editable 모드 설치
pip install -e .

# 설치 확인
agy-admin-cli --help
```

---

## 5. 사용자 온보딩 흐름

1. **라이선스 할당**: Google Workspace 관리 콘솔 또는 Cloud Identity에서 Gemini Enterprise 라이선스를 할당합니다.
2. **초기 접근 권한 부여**:
   ```bash
   # 단일 사용자 온보딩
   agy-admin-cli allow dev1@company.com --project <PROJECT_ID>

   # 파일 기반 일괄 온보딩
   agy-admin-cli allow --file users.txt --project <PROJECT_ID>
   ```
3. **사용자 클라이언트 로그인**: 사용자가 Antigravity 클라이언트에서 회사 Google 계정으로 로그인하고 `<PROJECT_ID>`를 입력합니다.

---

## 6. CLI 사용 가이드 (`agy-admin-cli`)

### 1) 사용량 조회 (`list`)
```bash
# 기본: 이번 달(calendar), 토큰 내림차순 정렬
agy-admin-cli list --project <PROJECT_ID>

# 집계 기간 지정 (daily, weekly, monthly, all)
agy-admin-cli list --period daily --project <PROJECT_ID>

# 슬라이딩 24시간 윈도우
agy-admin-cli list --period daily --window rolling --project <PROJECT_ID>

# 사용자명, 상태, 최소 토큰 기준 필터링
# 허용 상태 필터: all, ENFORCEABLE_ALLOWED, CAPPED_BY_TOOL,
#                 BLOCKED_BY_ADMIN, NOT_ENFORCEABLE, NO_ACCESS, UNKNOWN
agy-admin-cli list --filter-user "devuser01" --filter-status ENFORCEABLE_ALLOWED --min-tokens 50000 --project <PROJECT_ID>

# 자동 제어가 불가능한 사용자 목록 확인
agy-admin-cli list --filter-status NOT_ENFORCEABLE --project <PROJECT_ID>

# JSON 또는 CSV 파일로 내보내기
agy-admin-cli list --format json --project <PROJECT_ID>
agy-admin-cli list --format csv --project <PROJECT_ID>
```

### 2) 특정 사용자 상세 조회 (`user`)
```bash
agy-admin-cli user dev1@company.com dev2@company.com --project <PROJECT_ID>
agy-admin-cli user --file users.txt --format json --project <PROJECT_ID>
```

### 3) 수동 접근 관리 (`allow`, `disallow`)
```bash
# 접근 권한 부여
agy-admin-cli allow dev1@company.com --project <PROJECT_ID>

# 접근 제한 (CustomAntigravityAdminBlocked 부여)
agy-admin-cli disallow dev1@company.com --reason "Offboarded" --project <PROJECT_ID>

# IAM 변경 없이 시뮬레이션 (dry-run)
agy-admin-cli disallow dev1@company.com --dry-run --project <PROJECT_ID>
```

개별 프로젝트 바인딩으로 접근 권한을 회수할 수 없는 사용자에 대해서는 IAM을 변경하지 않습니다. 해당 계정은 상태 및 사유 코드와 함께 **수동 조치 필요(Manual Action Required)** 항목에 표시되며, 프로세스는 종료 코드 `2`를 반환합니다.

#### 수동 조치 필요 계정 처리 방법

이런 계정을 도구가 강제로 처리하도록 하는 옵션은 없습니다. 기본 역할 바인딩을 제거해도 접근 권한이 회수되지 않고, 마커 역할을 부여하면 권한을 제거하는 대신 오히려 추가하게 되기 때문입니다. 사유 코드별 접근 권한 출처는 다음과 같습니다.

| 사유 코드 | 접근 권한 출처 |
|---|---|
| `GROUP_GRANT_PRESENT` | `group:` 또는 `domain:` 멤버가 기본 역할 보유 |
| `PRIVILEGED_ROLE` | `roles/owner` 또는 `roles/editor` |
| `OTHER_ACCESS_ROLE` | `roles/discoveryengine.admin` 등 다른 접근 부여 역할 |
| `INHERITED_BINDING` | 상위 폴더 또는 조직 단위 바인딩 |
| `CONFLICTING_BINDINGS` | 조건부 바인딩이거나 기본 역할과 마커 역할 동시 보유 |
| `POLICY_UNREADABLE` | 프로젝트 IAM 정책 조회 실패 |
| `ANCESTOR_UNCHECKED` | 상위 정책 조회 불가 |

조치 전 대상 계정을 확인하려면:

```bash
# 도구가 제어할 수 없는 계정과 사유 코드 조회
agy-admin-cli list --filter-status NOT_ENFORCEABLE --project <PROJECT_ID>

# 기본 역할을 보유한 주체 확인 (그룹 포함)
gcloud projects get-iam-policy <PROJECT_ID> \
  --flatten="bindings[].members" \
  --filter="bindings.role:roles/discoveryengine.agentspaceUser" \
  --format="value(bindings.members)"
```

그룹 멤버십이나 역할을 정리한 뒤 `agy-admin-cli user <email>`을 다시 실행하여 해당 계정이 `NO_ACCESS`로 표시되는지 확인하십시오.

### 4) 캡 평가 및 집행 (`cap apply`)
```bash
# 일일 500,000 토큰 캡 설정
agy-admin-cli cap apply --period daily --tokens 500000 --project <PROJECT_ID>

# 일일 롤링 윈도우(최근 24시간) 800,000 토큰 캡 설정
agy-admin-cli cap apply --period daily --window rolling --tokens 800000 --project <PROJECT_ID>

# 요청 수와 토큰 수를 함께 제한
agy-admin-cli cap apply --period daily --requests 1000 --tokens 500000 --project <PROJECT_ID>

# JSON 설정 파일을 사용한 기본값 및 사용자별 맞춤 캡 적용
agy-admin-cli cap apply --period monthly --config-file user_caps.json --project <PROJECT_ID>

# IAM 변경 없이 평가 결과 미리보기
agy-admin-cli cap apply --period daily --tokens 500000 --dry-run --project <PROJECT_ID>
```

#### 사용자별 맞춤 캡 설정 (`user_caps.json`)
특정 사용자(VIP, 리드 개발자 등)에게 다른 한도를 적용하면서 기본 한도를 함께 정의할 수 있습니다:
```json
{
  "default": {
    "max_tokens": 5000000
  },
  "overrides": {
    "user@example.com": {
      "max_tokens": 15000000
    },
    "lead@example.com": {
      "max_tokens": 25000000
    }
  }
}
```
* `overrides`에 명시된 사용자는 맞춤 한도로 평가됩니다.
* 그 외 사용자는 `default` 한도로 평가됩니다.
* 이메일 대소문자는 구분하지 않습니다.

실행 결과 리포트 구성:
1. **Cap Enforcement Summary**: 제어율(Coverage), 집행 건수, 수동 조치 필요 대상 건수 요약
2. **Cap Violations**: 사용자별 조치 상세 (`DISALLOWED`, `ALREADY CAPPED`, `NOT ENFORCEABLE`)
3. **Manual Action Required**: 개별 바인딩 방식으로는 차단할 수 없는 캡 위반자 목록

### 5) 종료 코드

| 코드 | 의미 |
|---|---|
| `0` | 정상 완료. 요청한 작업이 모두 적용되었거나 이미 충족됨 |
| `1` | 인자 지정 오류 또는 사용자 파일 형식 오류 |
| `2` | 사용자 상태가 적합하지 않아 하나 이상의 작업이 거부됨 |
| `3` | 안전 게이트에 의해 사이클이 중단됨. IAM 정책은 변경되지 않음 |

---

## 7. Cloud Run 배치 잡 (자동 집행)

Cloud Scheduler로 예약된 Cloud Run Jobs를 사용하여 집행 사이클을 자동화합니다.

### 1) Cloud Run Job 배포
```bash
# 기본 배포 (15분 주기 실행, 사전 점검 포함)
./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"

# 초기 검증을 위한 dry-run 모드 배포
DRY_RUN=true ./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"

# 임계값, 사용자별 맞춤 캡(user_caps.json) 및 알림 설정을 지정한 배포
CAP_PERIOD="monthly" \
CAP_CONFIG_FILE="user_caps.json" \
ALERT_WEBHOOK_URL="https://chat.googleapis.com/v1/spaces/..." \
./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "0 0 1 * *"

# 사전 점검 지적사항을 감수하고 배포하는 경우
SKIP_PREFLIGHT=true ./scripts/deploy_cloud_run.sh <PROJECT_ID> asia-south1 "*/15 * * * *"
```

### 2) 수동 실행 및 로그 확인
```bash
# 즉시 실행 트리거
gcloud run jobs execute agy-cap-enforcer --region=asia-south1 --project=<PROJECT_ID>

# 실행 로그 실시간 확인
gcloud beta run jobs executions logs tail \
  $(gcloud run jobs executions list --job=agy-cap-enforcer --region=asia-south1 --project=<PROJECT_ID> --limit=1 --format="value(name)") \
  --project=<PROJECT_ID>

# 관리 감사 로그 조회
gcloud logging read \
  'logName="projects/<PROJECT_ID>/logs/agy-admin%2Fadmin_actions"' \
  --project=<PROJECT_ID> --limit=50
```

---

## 8. 설정 및 환경 변수

### 집행 관련 설정

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `GCP_PROJECT` | - | 대상 Google Cloud 프로젝트 ID |
| `CAP_PERIOD` | `daily` | 집계 기간 (`daily`, `weekly`, `monthly`) |
| `WINDOW_TYPE` | `calendar` | 윈도우 계산 방식 (`calendar`: UTC 00:00 기준, `rolling`: 슬라이딩 윈도우) |
| `CAP_TOKENS` | - | 토큰 캡 임계값 (예: `800000`) |
| `CAP_REQUESTS` | - | 요청 수 캡 임계값 (예: `1000`) |
| `CAP_CONFIG_FILE` | - | 기본 한도 및 사용자별 맞춤 한도를 정의한 JSON 파일 경로 (예: `user_caps.json`) |
| `IAM_DISALLOW_MODE` | `custom_role` | 차단 방식 (`custom_role` 또는 `revoke`) |
| `DRY_RUN` | `false` | `true` 설정 시 IAM 변경 없이 시뮬레이션 |
| `INTERVAL_MINUTES` | `0` | `0`은 1회 실행 후 종료. Cloud Run Jobs에서는 `0`으로 설정 |
| `ALERT_WEBHOOK_URL` | - | 알림용 Slack 또는 Google Chat 웹훅 URL |

### 역할 및 분류 설정

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `AGY_ALLOWED_ROLE` | `roles/discoveryengine.agentspaceUser` | Antigravity 접근 권한을 부여하는 기본 역할 |
| `AGY_CAP_ROLE_ID` | `CustomAntigravityCapBlocked` | 자동 캡 사이클이 부여하는 마커 역할 |
| `AGY_ADMIN_ROLE_ID` | `CustomAntigravityAdminBlocked` | 수동 `disallow`가 부여하는 마커 역할 |
| `AGY_CUSTOM_RESTRICTED_ROLE_ID` | `CustomAntigravityRestrictedUser` | v0.1.0 레거시 마커 역할 (`BLOCKED_BY_ADMIN`으로 취급) |
| `AGY_EXTRA_ACCESS_ROLES` | - | 접근 권한을 부여하는 추가 역할 목록 (쉼표 구분) |
| `AGY_LOG_ID` | `businessaicode.googleapis.com/inference_response` | 사용량 로그 스트림 이름 |

### 안전 게이트 설정

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `AGY_REQUIRE_ANCESTOR_CHECK` | `false` | 상위 폴더/조직 정책 검사 여부. 활성화 후 조회 실패 시 전원 `UNKNOWN` 처리 |
| `AGY_ALLOW_GROUP_COEXISTENCE` | `false` | `true` 설정 시 역할에 그룹 바인딩이 있어도 개별 바인딩 관리를 허용 |
| `AGY_MAX_CHANGES_ABS` | `10` | 서킷 브레이커 최소 변경 건수 하한 |
| `AGY_MAX_CHANGES_RATIO` | `0.2` | 서킷 브레이커 변경 비율 (`max(abs, ratio x 전체인원)`) |

---

## 9. 테스트 실행

```bash
pytest -v tests/
```

테스트 스위트는 다음 항목을 검증합니다:
- 6개 상태 분류 로직 및 사유 코드 할당
- 사용자별 맞춤 캡 한도 및 오버라이드 평가 (`user_caps.json`)
- 주요 예외 상황 회귀 테스트 (그룹 바인딩, 로그 누락, 정책 조회 오류 등)
- 안전 게이트 G1~G5 및 서킷 브레이커 동작
- Resource Manager SDK 버전 3 정책 읽기 및 배치 쓰기
- 커버리지 지표 계산 및 수동 조치 항목 보고
- 감사 로그 구조 및 웹훅 페이로드 생성
- CLI 인자 파싱 및 명령어 종료 코드

---

## 10. 참고 문서

- [Gemini Enterprise - Configure AI developer tools settings](https://docs.cloud.google.com/gemini/enterprise/docs/ai-developer-tools-settings)
- [Gemini Enterprise - Create custom roles to restrict access to AI developer tools](https://cloud.google.com/gemini/enterprise/docs/ai-developer-tools-creating-custom-roles)
- [Discovery Engine IAM Access Control](https://cloud.google.com/generative-ai-app-builder/docs/access-control)
- [IAM Conditions and policy versions](https://cloud.google.com/iam/docs/policies#versions)

---

## 11. 알려진 제약사항

### 11.1 개별 `user:` 바인딩만 제어 가능
프로젝트 수준의 IAM 정책만 수정하므로 Google 그룹 멤버십, 도메인 단위 바인딩, 상위 폴더/조직 상속 권한은 변경할 수 없습니다. 해당 경로로 권한을 부여받은 사용자는 `NOT_ENFORCEABLE`로 분류되며 관리자가 직접 조치해야 합니다.

이런 계정에 대한 우회 옵션은 제공하지 않습니다. 기본 역할 바인딩을 제거해도 접근 권한이 회수되지 않고, 마커 역할을 부여하면 권한을 제거하는 대신 추가하게 되므로, 명령어는 작업을 거부하고 필요한 조치 방법을 안내합니다.

### 11.2 상위 리소스(폴더/조직) 상속 권한 미검사 (기본값)
`AGY_REQUIRE_ANCESTOR_CHECK`의 기본값은 `false`입니다. 상위 폴더나 조직 단위 정책 조회에는 프로젝트 서비스 계정이 일반적으로 보유하지 않는 상위 권한이 필요하기 때문입니다. 비활성화 상태에서는 상속된 권한이 감지되지 않으며, 활성화 시 상위 정책 조회 권한이 없으면 모든 사용자가 `UNKNOWN`으로 분류되어 작업이 중단됩니다.

### 11.3 조건부 IAM 바인딩 변경 미지원
조건(IAM Condition)이 설정된 바인딩은 조건 유실을 방지하기 위해 수정하지 않습니다. 조건부 바인딩으로 권한을 얻은 사용자는 `NOT_ENFORCEABLE (CONFLICTING_BINDINGS)`로 분류됩니다.

### 11.4 `--mode revoke` 사용 시 자동 복구 미지원
`revoke` 모드는 대상 사용자의 `roles/discoveryengine.agentspaceUser` 역할 바인딩을 제거하며, 대체 마커 역할을 부여하지 않습니다. 이 경우 해당 계정이 IAM 정책상 미부여 일반 사용자와 동일한 상태(`NO_ACCESS`)가 되어 차단 이력을 식별할 수 없으므로, 캡 초기화 시에도 자동으로 권한이 복구되지 않습니다. 자동 복구가 필요한 환경에서는 기본값인 `custom_role` 모드를 사용하십시오.

### 11.5 주기적 배치 실행에 따른 지연
실시간 API 차단이 아닌 스케줄러 기반 배치 작업이므로, 캡 초과 시점부터 다음 실행 주기(기본 15분)까지는 사용이 유지될 수 있습니다.

### 11.6 Calendar 윈도우 기준 시점 (UTC)
`--window calendar`는 UTC 기준(00:00 UTC)으로 일/주/월 경계를 계산합니다. 현지 업무 시간 기준의 슬라이딩 조회가 필요한 경우 `--window rolling`을 사용하십시오.

### 11.7 `--period all` 쿼리 기간 제한 (90일)
Cloud Logging 쿼리 성능과 비용을 고려하여 `all` 기간은 최근 90일로 제한됩니다.

### 11.8 사전 정의된 특권 역할 외 커스텀 역할 미감지
`roles/owner`, `roles/editor` 및 주요 Discovery Engine 역할은 자동으로 감지되나, 조직 내에서 별도로 생성한 커스텀 역할은 자동 감지되지 않습니다. 해당 역할이 있다면 `AGY_EXTRA_ACCESS_ROLES`에 명시해야 합니다.

### 11.9 Gemini Enterprise 메타데이터 로깅 의존성
콘솔에서 Metadata Logging이 비활성화되면 사용량 로그가 발생하지 않습니다. 게이트 G3가 대규모 오작동은 차단하지만 캡 탐지 역시 중단되므로 콘솔 설정을 유지해야 합니다.

### 11.10 서비스 계정 및 비개인 주체 제외
`user:` 형식의 계정만 관리 대상으로 분류합니다. 서비스 계정이나 시스템 계정의 사용량은 메트릭 조회는 가능하나 차단 대상에는 포함되지 않습니다.
