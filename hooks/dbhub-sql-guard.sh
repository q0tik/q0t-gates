#!/usr/bin/env bash
# PreToolUse(mcp__dbhub__execute_sql): страж write-операций в прод-БД BSGDATA.
#
# SELECT проходит молча. Любой DML/DDL требует НАЖАТИЯ ЮЗЕРА — но подтверждение
# спрашивает сам хук (Telegram inline-кнопки, фолбэк — нативный macOS-диалог),
# а не permissionDecision=ask.
#
# Почему не ask: ask лишь возвращает решение в обычный permission-flow, где его
# перебивает любое allow — правило в settings*.json ИЛИ сессионный кэш от
# когда-то нажатого «не спрашивать больше». Проверено вживую 2026-08-17:
# UPDATE ушёл в прод молча, хотя хук вернул ask. deny перебить нельзя, поэтому
# схема такая: спрашиваем сами → allow только после нажатия, иначе deny.
# Fail-closed: нет сети, Telegram не ответил, таймаут, ошибка парсинга,
# неизвестный ответ, нет GUI, закрытое окно → deny.
#
# Канал подтверждения — Telegram: с телефона видно ВЕСЬ запрос и жать можно
# откуда угодно. Отдельный бот-токен, НЕ токен q0t-claude-assistant: два
# getUpdates на одном токене конфликтуют (а если у того выставлен webhook —
# наш getUpdates получит 409 и заодно сломает прод-ассистента).
#
# Конфиг (вне git, режим 600): ~/.claude/dbhub-telegram.env
#   пример — .claude/hooks/dbhub-telegram.env.example
# Откат на старый macOS-диалог — одна строка в конфиге:
#   DBHUB_APPROVAL_CHANNEL=osascript
# См. .claude/rules/sql-storedprocs.md

input=$(cat)

SQL=$(printf '%s' "$input" | jq -r '.tool_input.sql // .tool_input.query // empty' 2>/dev/null)
[ -n "$SQL" ] || exit 0

# Срезаем строковые литералы и комментарии, чтобы 'update' внутри текста
# или в -- комментарии не давал ложное срабатывание.
STRIPPED=$(printf '%s' "$SQL" \
  | sed -E "s/'[^']*'/''/g" \
  | sed -E 's/--[^\n]*//g' \
  | sed -E 's|/\*[^*]*\*+([^/*][^*]*\*+)*/||g')

# Необратимое / разрушающее — отдельным списком, для более громкого warning.
DESTRUCTIVE='DROP|TRUNCATE|DELETE|ALTER|REVOKE'
# REPLACE намеренно НЕ в списке: как самостоятельное слово это read-only
# строковая функция replace(), а `CREATE OR REPLACE` и так ловится по CREATE.
DANGER="$DESTRUCTIVE|INSERT|UPDATE|CREATE|MERGE|UPSERT|GRANT|EXEC|EXECUTE|CALL|COPY|VACUUM|REINDEX"

# Запись через ХРАНИМКУ ключевыми словами не ловится: в `SELECT
# modify_janus_settings('INSERT', ...)` слово INSERT лежит внутри литерала, а
# литералы срезаются выше — от запроса остаётся `SELECT modify_...('', ...)`,
# то есть на вид read-only. А в QB через хранимки правится половина всего.
# Ловим по ИМЕНИ функции: оно вне кавычек и срез его не трогает.
PROC_WRITE='(modify|insert|update|delete|upsert|merge|claim|cleanup|remove|write|save|apply|recalc|fix|set|add)_[a-z0-9_]*[[:space:]]*\('
# Служебные функции Postgres с теми же префиксами — не запись в наши таблицы.
PROC_SAFE='set_config|set_bit|set_byte|set_masklen|add_month'

# Безопасные отсеиваются ПОСЛЕ извлечения, а не вырезанием из текста: BSD-sed
# в macOS не понимает \b, и попытка вырезать по границе слова молча ничего не
# делала — set_config уходил на подтверждение как запись.
PROC_HIT=$(printf '%s' "$STRIPPED" | grep -ioE "\b$PROC_WRITE" \
  | sed -E 's/[[:space:]]*\($//' | tr '[:upper:]' '[:lower:]' \
  | grep -ivE "^($PROC_SAFE)$" | sort -u | paste -sd, -)
# call_pg_proc — обёртка SDK: имя проца лежит внутри аргументов, то есть вызов
# заведомо на write-пути, даже если само имя ни на что не похоже.
if printf '%s' "$STRIPPED" | grep -iqE 'call_pg_proc[[:space:]]*\('; then
  PROC_HIT="${PROC_HIT:+$PROC_HIT,}call_pg_proc"
fi

# Безопасный запрос — разрешаем прямо здесь, самим хуком: allow-правила для
# mcp__dbhub__execute_sql в permissions держать нельзя (см. шапку), а
# «молчаливость» SELECT'ов нужна.
if ! printf '%s' "$STRIPPED" | grep -iqE "\\b($DANGER)\\b" && [ -z "$PROC_HIT" ]; then
  printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"read-only SQL"}}'
  exit 0
fi

MATCHED=$(printf '%s' "$STRIPPED" | grep -ioE "\\b($DANGER)\\b" \
  | tr '[:lower:]' '[:upper:]' | sort -u | paste -sd, -)
# Имя хранимки — обязательно в сообщение: иначе человек видит запрос без единого
# ключевого слова и не понимает, за что его спрашивают.
if [ -n "$PROC_HIT" ]; then
  if [ -n "$MATCHED" ]; then
    MATCHED="$MATCHED, хранимка: $PROC_HIT"
  else
    MATCHED="хранимка: $PROC_HIT"
  fi
fi

if printf '%s' "$STRIPPED" | grep -iqE "\\b($DESTRUCTIVE)\\b"; then
  BANNER="🛑 РАЗРУШАЮЩАЯ ОПЕРАЦИЯ В ПРОДЕ BSGDATA"
else
  BANNER="⚠️ ЗАПИСЬ В ПРОД-БД BSGDATA"
fi

# Первые строки запроса — для systemMessage, который видит Claude (не человек).
# Человеку в Telegram уходит ВЕСЬ запрос целиком, без обрезки.
PREVIEW=$(printf '%s' "$SQL" | head -c 700)

deny() {
  jq -n --arg banner "$BANNER" --arg kw "$MATCHED" --arg why "$1" --arg preview "$PREVIEW" '
  {
    systemMessage: ($banner + "\nКлючевые слова: " + $kw + "\n" + $preview + "\n" + $why),
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: ($banner + " — " + $why + " Ключевые слова: " + $kw + ".")
    }
  }'
  exit 0
}

allow() {  # $1 — как именно подтвердили
  # Аудит: подтверждённые write'ы в прод логируем — их не видно ни в git,
  # ни в CI (хранимки правятся прямо в БД, миграций нет).
  printf '%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$1" "$MATCHED" \
    "$(printf '%s' "$SQL" | tr '\n' ' ')" \
    >> "$HOME/.claude/dbhub-writes.log" 2>/dev/null
  jq -n --arg kw "$MATCHED" --arg via "$1" '
  {
    systemMessage: ("✅ Write в BSGDATA подтверждён вручную (" + $kw + ", канал: " + $via + "), записан в ~/.claude/dbhub-writes.log"),
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: ("Юзер подтвердил write (" + $via + "): " + $kw)
    }
  }'
  exit 0
}

# ─────────────────────────── конфиг ───────────────────────────

CFG="${DBHUB_APPROVAL_ENV:-$HOME/.claude/dbhub-telegram.env}"

cfg_get() {  # cfg_get KEY — значение из env-файла, без source (без eval чужого кода)
  [ -r "$CFG" ] || return 0
  grep -E "^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=" "$CFG" 2>/dev/null \
    | tail -n1 \
    | sed -E "s/^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=[[:space:]]*//" \
    | sed -E 's/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/' \
    | tr -d '\r'
}

keychain_get() {  # запасной источник токена, если env-файла нет
  command -v security >/dev/null 2>&1 || return 0
  security find-generic-password -s "$1" -w 2>/dev/null
}

CHANNEL=$(cfg_get DBHUB_APPROVAL_CHANNEL); CHANNEL="${CHANNEL:-telegram}"
TG_TOKEN=$(cfg_get DBHUB_APPROVAL_BOT_TOKEN)
[ -n "$TG_TOKEN" ] || TG_TOKEN=$(keychain_get dbhub-approval-bot-token)
TG_CHAT=$(cfg_get DBHUB_APPROVAL_CHAT_ID)
[ -n "$TG_CHAT" ] || TG_CHAT=$(keychain_get dbhub-approval-chat-id)

# Сколько ждём нажатия. ДОЛЖНО быть заметно меньше timeout хука в
# .claude/settings.json (600с): если хук оборвут по таймауту, его решение не
# применится вовсе — а это fail-open. 540с ждём + запас 60с на сеть/выход.
WAIT_SECONDS=$(cfg_get DBHUB_APPROVAL_TIMEOUT); WAIT_SECONDS="${WAIT_SECONDS:-480}"
case "$WAIT_SECONDS" in ''|*[!0-9]*) WAIT_SECONDS=480 ;; esac

# ──────────────────────── macOS-диалог ────────────────────────

ask_osascript() {  # печатает ALLOW / DENY / UNREACHABLE
  command -v osascript >/dev/null 2>&1 || { note_gui_err "нет osascript"; printf 'UNREACHABLE'; return; }
  # Аргументы уходят через argv, поэтому кавычки и переносы в SQL не ломают
  # AppleScript и ничего не надо экранировать.
  local dlg_wait=$(( WAIT_SECONDS < 90 ? WAIT_SECONDS : 90 ))
  local r
  r=$(osascript - "$BANNER" "$MATCHED" "$(printf '%s' "$SQL" | head -c 700)" "$dlg_wait" <<'APPLESCRIPT' 2>&1
on run argv
  set theBanner to item 1 of argv
  set theKw to item 2 of argv
  set theSql to item 3 of argv
  set theWait to (item 4 of argv) as integer
  set theMsg to theBanner & return & "Ключевые слова: " & theKw & return & return & theSql & return & return & "Выполнить этот запрос в проде BSGDATA?"
  try
    tell application "System Events"
      activate
      display dialog theMsg with title "dbhub guard — запись в прод" buttons {"Отклонить", "Выполнить"} default button "Отклонить" with icon caution giving up after theWait
      set r to result
    end tell
    if (button returned of r) is "Выполнить" and (gave up of r) is false then
      return "ALLOW"
    end if
    return "DENY"
  on error e number n
    return "ERROR " & n & ": " & e
  end try
end run
APPLESCRIPT
)
  case "$r" in
    ALLOW) printf 'ALLOW' ;;
    DENY)  printf 'DENY' ;;
    # Нет GUI / нет доступа к System Events — спросить некого, это не отказ юзера.
    *)     note_gui_err "$(printf '%s' "$r" | head -c 200)"; printf 'UNREACHABLE' ;;
  esac
}

# ───────────────────────── Telegram ──────────────────────────

ERRFILE=$(mktemp -t dbhub-guard-err)      # почему не сработал Telegram
ERRFILE_GUI=$(mktemp -t dbhub-guard-gui)  # почему не сработал osascript
trap 'rm -f "$ERRFILE" "$ERRFILE_GUI"' EXIT
note_err() { printf '%s' "$1" > "$ERRFILE"; }
note_gui_err() { printf '%s' "$1" > "$ERRFILE_GUI"; }
# DBHUB_APPROVAL_API_BASE — только для тестов хука (мок-сервер вместо Telegram).
API="${DBHUB_APPROVAL_API_BASE:-https://api.telegram.org}/bot${TG_TOKEN}"
LOCKDIR="$HOME/.claude/.dbhub-approval.lock"

scrub() { sed -E "s#bot[0-9]+:[A-Za-z0-9_-]+#bot<TOKEN>#g"; }  # токен не должен утечь в логи/вывод

tg_api() {  # tg_api METHOD <json-на-stdin>; печатает тело ответа, код возврата curl — статус
  curl -sS --max-time 35 -X POST \
    -H 'Content-Type: application/json' \
    --data-binary @- "$API/$1" 2>/dev/null
}

tg_api_quick() {  # добивающие вызовы после решения: результат уже принят, ждать их долго нельзя
  curl -sS --max-time 10 -X POST \
    -H 'Content-Type: application/json' \
    --data-binary @- "$API/$1" 2>/dev/null
}

html_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

lock_acquire() {
  # На macOS нет flock. Каталог как мьютекс: два одновременных подтверждения
  # передрались бы за getUpdates и могли бы «подобрать» чужое нажатие.
  local waited=0
  while ! mkdir "$LOCKDIR" 2>/dev/null; do
    # Снимаем зависший лок старше 20 минут (дольше любого нашего ожидания).
    if [ -n "$(find "$LOCKDIR" -maxdepth 0 -mmin +20 2>/dev/null)" ]; then
      rmdir "$LOCKDIR" 2>/dev/null
      continue
    fi
    waited=$((waited + 2))
    [ "$waited" -gt 60 ] && return 1
    sleep 2
  done
  return 0
}
lock_release() { rmdir "$LOCKDIR" 2>/dev/null; }

ask_telegram() {  # печатает ALLOW / DENY / UNREACHABLE
  if [ -z "$TG_TOKEN" ] || [ -z "$TG_CHAT" ]; then
    note_err "нет токена/chat_id в $CFG"; printf 'UNREACHABLE'; return
  fi
  command -v curl >/dev/null 2>&1 || { note_err "нет curl"; printf 'UNREACHABLE'; return; }

  if ! lock_acquire; then
    # Не UNREACHABLE: спрашивать через osascript тут нельзя — параллельное
    # подтверждение уже идёт, тихо разрешать второй запрос нельзя тем более.
    note_err "параллельное подтверждение уже идёт (lock)"; printf 'LOCKED'; return
  fi
  trap 'lock_release' EXIT

  # Один бюджет на весь обмен: слив очереди + отправка + ожидание. Иначе долгая
  # отправка сдвигала бы дедлайн и хук рисковал не уложиться в timeout из
  # settings.json — а обрыв по timeout это fail-open.
  local deadline; deadline=$(( $(date +%s) + WAIT_SECONDS ))

  local nonce; nonce=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
  [ -n "$nonce" ] || nonce="$$-$(date +%s)"

  # 1. Сбрасываем накопившиеся апдейты: старое нажатие не должно подтвердить
  #    новый запрос. Забираем последний update_id и двигаем offset за него.
  local drain offset
  drain=$(printf '{"timeout":0,"limit":100,"allowed_updates":["callback_query"]}' | tg_api getUpdates)
  offset=$(printf '%s' "$drain" | jq -r '(.result // []) | if length>0 then (max_by(.update_id).update_id + 1) else 0 end' 2>/dev/null)
  case "$offset" in ''|*[!0-9]*) offset=0 ;; esac
  if [ "$(printf '%s' "$drain" | jq -r '.ok // false' 2>/dev/null)" != "true" ]; then
    note_err "getUpdates не отвечает: $(printf '%s' "$drain" | head -c 200 | scrub)"
    lock_release; printf 'UNREACHABLE'; return
  fi

  # 2. Отправляем запрос с кнопками. Весь SQL целиком: влезает в 4096 — текстом,
  #    не влезает — файлом (sendDocument), чтобы человек видел ВЕСЬ запрос.
  local kb head_txt esc_sql body resp msg_id
  kb=$(jq -nc --arg y "ok:$nonce" --arg n "no:$nonce" \
    '{inline_keyboard:[[{text:"✅ Выполнить",callback_data:$y},{text:"🛑 Отклонить",callback_data:$n}]]}')
  head_txt="$(html_escape "$BANNER")
<b>Ключевые слова:</b> $(html_escape "$MATCHED")
<b>Хост:</b> $(html_escape "$(hostname -s 2>/dev/null)")  <b>Время:</b> $(date '+%F %T')"
  esc_sql=$(html_escape "$SQL")

  if [ "${#esc_sql}" -le 3600 ]; then
    body=$(jq -nc --arg chat "$TG_CHAT" \
      --arg text "$head_txt

<pre>$esc_sql</pre>

Выполнить этот запрос в проде BSGDATA?" \
      --argjson kb "$kb" \
      '{chat_id:$chat,text:$text,parse_mode:"HTML",reply_markup:$kb}')
    resp=$(printf '%s' "$body" | tg_api sendMessage)
  else
    # Длинный запрос — полным файлом, ничего не режем. Caption ≤1024 символов.
    local tmp; tmp=$(mktemp -t dbhub-sql)
    printf '%s' "$SQL" > "$tmp"
    resp=$(curl -sS --max-time 60 \
      -F "chat_id=$TG_CHAT" \
      -F "document=@$tmp;filename=query.sql;type=text/plain" \
      -F "parse_mode=HTML" \
      -F "caption=$head_txt
<b>Длина:</b> ${#SQL} символов — весь запрос во вложении.
Выполнить его в проде BSGDATA?" \
      -F "reply_markup=$kb" \
      "$API/sendDocument" 2>/dev/null)
    rm -f "$tmp"
  fi

  if [ "$(printf '%s' "$resp" | jq -r '.ok // false' 2>/dev/null)" != "true" ]; then
    note_err "отправка не прошла: $(printf '%s' "$resp" | head -c 200 | scrub)"
    lock_release; printf 'UNREACHABLE'; return
  fi
  msg_id=$(printf '%s' "$resp" | jq -r '.result.message_id // empty' 2>/dev/null)
  if [ -z "$msg_id" ]; then
    note_err "в ответе нет message_id"
    lock_release; printf 'UNREACHABLE'; return
  fi

  # 3. Ждём нажатие. Принимаем ТОЛЬКО callback с нашим nonce, с нашего
  #    сообщения и из нашего чата — всё прочее пропускаем мимо.
  local verdict upd n i data cb_id cb_chat cb_msg remain poll
  verdict=""
  while :; do
    # Long-poll обязан кончиться НЕ ПОЗЖЕ дедлайна: иначе запрос, начатый за
    # секунду до него, тянул бы ещё 25с сверх бюджета.
    remain=$(( deadline - $(date +%s) ))
    [ "$remain" -le 0 ] && break
    poll=$(( remain > 25 ? 25 : remain ))
    upd=$(jq -nc --argjson off "$offset" --argjson t "$poll" \
      '{timeout:$t,limit:20,offset:$off,allowed_updates:["callback_query"]}' | tg_api getUpdates)
    [ "$(printf '%s' "$upd" | jq -r '.ok // false' 2>/dev/null)" = "true" ] || { sleep 3; continue; }
    n=$(printf '%s' "$upd" | jq -r '(.result // []) | length' 2>/dev/null)
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    i=0
    while [ "$i" -lt "$n" ]; do
      offset=$(printf '%s' "$upd" | jq -r ".result[$i].update_id + 1")
      data=$(printf '%s' "$upd" | jq -r ".result[$i].callback_query.data // empty")
      cb_id=$(printf '%s' "$upd" | jq -r ".result[$i].callback_query.id // empty")
      cb_chat=$(printf '%s' "$upd" | jq -r ".result[$i].callback_query.message.chat.id // empty")
      cb_msg=$(printf '%s' "$upd" | jq -r ".result[$i].callback_query.message.message_id // empty")
      i=$((i + 1))
      [ "$cb_chat" = "$TG_CHAT" ] && [ "$cb_msg" = "$msg_id" ] || continue
      case "$data" in
        "ok:$nonce") verdict=ALLOW ;;
        "no:$nonce") verdict=DENY ;;
        *) continue ;;
      esac
      jq -nc --arg id "$cb_id" --arg t "$( [ "$verdict" = ALLOW ] && echo '✅ Выполняю' || echo '🛑 Отклонено' )" \
        '{callback_query_id:$id,text:$t}' | tg_api answerCallbackQuery >/dev/null
      break
    done
    [ -n "$verdict" ] && break
  done

  # 4. Гасим кнопки, чтобы по этому сообщению нельзя было нажать второй раз.
  local mark
  case "$verdict" in
    ALLOW) mark="✅ ПОДТВЕРЖДЕНО — запрос уходит в прод" ;;
    DENY)  mark="🛑 ОТКЛОНЕНО" ;;
    *)     mark="⏱ ТАЙМАУТ (${WAIT_SECONDS}с) — отклонено" ;;
  esac
  jq -nc --arg chat "$TG_CHAT" --argjson mid "$msg_id" \
    '{chat_id:$chat,message_id:$mid}' | tg_api_quick editMessageReplyMarkup >/dev/null
  jq -nc --arg chat "$TG_CHAT" --argjson mid "$msg_id" --arg t "$mark ($(date '+%H:%M:%S'))" \
    '{chat_id:$chat,reply_to_message_id:$mid,text:$t,allow_sending_without_reply:true}' \
    | tg_api_quick sendMessage >/dev/null

  lock_release
  # Пусто = никто не нажал за отведённое время. Fail-closed: это DENY, а не
  # повод переспрашивать в GUI — 8 минут уже прошло.
  printf '%s' "${verdict:-DENY}"
}

# ───────────────────────── решение ───────────────────────────

VIA=""
if [ "$CHANNEL" = "telegram" ]; then
  ANSWER=$(ask_telegram); VIA="telegram"
  if [ "$ANSWER" = "UNREACHABLE" ]; then
    # Telegram не доставил сообщение — спрашиваем старым способом (req: fallback).
    # Таймаут/отказ сюда НЕ попадают: там человек уже видел запрос.
    ANSWER=$(ask_osascript); VIA="osascript-fallback"
  fi
else
  ANSWER=$(ask_osascript); VIA="osascript"
fi

case "$ANSWER" in
  ALLOW)
    allow "$VIA"
    ;;
  DENY)
    deny "Юзер отклонил запрос ($VIA) или истёк таймаут ожидания."
    ;;
  LOCKED)
    deny "Уже идёт другое подтверждение write в прод — этот запрос отклонён, повтори позже. ($(cat "$ERRFILE" 2>/dev/null))"
    ;;
  UNREACHABLE)
    deny "Спросить подтверждение негде. Telegram: $(cat "$ERRFILE" 2>/dev/null). GUI: $(cat "$ERRFILE_GUI" 2>/dev/null). Запрос отклонён."
    ;;
  *)
    deny "Подтверждение не отработало ($ANSWER) — запрос отклонён."
    ;;
esac
