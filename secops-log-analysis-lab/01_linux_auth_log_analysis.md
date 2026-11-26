# Rocky Linux 인증 로그 기반 침해사고 흔적 분석 실습

## 1. 실습 목적
* Rocky Linux 시스템의 `/var/log/secure` 로그 분석을 통한 비정상적인 로그인 시도 탐지
- `grep`, `awk`, `tail` 등 CLI 도구를 활용한 로그 파싱

<br>

## 2. 주요 실습 내용
* 로그인 실패 기록 추출: `sudo grep -i "fail" /var/log/secure`
* 권한 상승 시도 추적: `su` 및 `sudo` 명령어 실행 이력 확인
* **로그 파싱 및 통계 집계 파이프라인 구축**: 실패 로그에서 특정 필드 추출 후 빈도수 집계

![alt text](image/5.png)

<br>

## 3. 트러블슈팅 및 배운 점
* 문제 상황: 대소문자 구분(`grep` 기본 동작) 및 로그 포맷 차이로 인해 원하는 필드(`$(NF-3)`) 추출 시 공백 또는 세미콜론(;)이 출력됨.
* 해결 방법: `-i` 옵션을 추가하여 대소문자 무시 검색을 수행하고, 원본 로그 포맷을 먼저 `tail`로 검증한 뒤 필드 번호 재조정.

![alt text](image/2.png)
![alt text](image/4.png)

<br>

## 4. 실습 환경 구성 및 가상 로그 시뮬레이션

* 배경 : 클라우드/로컬 VM 환경은 초기 상태에서 실제 외부 침해 공격 로그가 부재하므로, 로그 파싱 및 탐지 파이프라인 검증의 한계가 존재한다.

* 해결 방안 : `/var/log/secure` 표준 포맷과 일치하는 가상의 브루트포스(무차별 대입) 공격 샘플 로그(`sample_secure.log`)를 제작하여 CLI 도구(`grep`, `awk`) 기반의 탐지 성능을 선제적으로 검증하였다.

<br>


1. 로그 파이프라인을 이용한 로그인 실패 확인

```bash
# 공격자 IP별 시도 횟수가 오름차순으로 출력
# sort & uniq -c : 각 IP가 몇 번 시도했는지 빈도수를 카운트
  grep "Failed password" sample_secure.log | awk '{print $(NF-3)}' | sort | uniq -c
```

```bash
# 가장 많이 공격을 시도한 IP를 한눈에 파악해야 할 때, 내림차순 정렬로 출력 -> sort -nr
  grep "Failed password" sample_secure.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```

* awk '{print $(NF-3)}' : 띄어쓰기 기준으로 줄을 쪼갠 뒤, 맨 끝(NF)에서 3칸 앞의 핵심 데이터만 추출.
* sort : 중복 데이터를 묶기 위해 오름차순으로 사전 정렬
* uniq -c : 연속된 중복 줄을 하나로 합치고, 반복된 횟수 (Count)를 앞에 출력.
* sort -n 옵션 : 숫자로 인식해서 크기를 비교
* sort -r 옵션 : 역순으로 정렬

![alt text](image/7.png)
![alt text](image/8.png)

<br>
<br>

2. 시간대별 공격 추이 확인하기

* 공격자가 언제 집중적으로 시도했는지를 파악

```bash
$ awk '{print $1, $2, $3}' sample_secure.log | uniq -c
```

<br>


3. 공격에 사용된 대상 계정 통계 내기

* 주로 어떤 계정을 노렸는지를 파악

```bash
$ grep "Failed password" sample_secure.log | awk '{print $(NF-5)}' | sort | uniq -c
```

* awk '{print $(NF-5)}' : 타겟 계정 이름 위치

<br>

![alt text](image/9.png)


<br>

## 5. 기억해 둘 것

1. tail 명령어 : 파일의 꼬리(Tail) 부분, 즉 맨 마지막(가장 최근에 기록된) 내용들을 화면에 보여주는 명령어.

<br>

* 기본형 : 파일의 맨 마지막 10줄을 보여줌

```bash
$ tail /var/log/secure
```

<br>

* 실시간 모니터링 (-f 옵션) : 터미널 창이 꺼지지 않고 대기 상태 후, 시스템에 새로운 로그가 찍히면 실시간으로 화면에 툭툭 추가되어 나타남. (관제 센터에서 모니터링할 때 가장 많이 쓰는 방식)
* 빠져나오고 싶을 때는 Ctrl + C

```bash
$ tail -f /var/log/secure
```

<br>

2. 실무 용어들

* 로그 파싱(Log Parsing) : 로그 파일에서 내가 원하는 알맹이 데이터만 쏙쏙 골라내는 과정

* 로그 집계/통계 (Log Aggregation) : 골라낸 데이터들을 정렬하고 중복 개수를 세서 랭킹이나 통계를 내는 과정

* 원라인 명령어(One-liner) : 터미널 한 줄에 파이프로 엮어서 빠르게 원하는 결과를 한 번에 뽑아내는 리눅스 특유의 기술 방식