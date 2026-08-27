// Package event разбирает JSON события, который Claude Code подаёт хуку на stdin.
package event

import (
	"encoding/json"
	"io"
	"path/filepath"
)

// Event — то, что пришло на stdin. Поля, которых нет у конкретного события,
// остаются нулевыми: движок не обязан знать полную схему харнесса, ему нужны
// только опорные точки.
type Event struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	CWD            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	Prompt         string          `json:"prompt"`

	// Raw — исходный JSON целиком: скрипты type = "script" получают его как есть,
	// чтобы движок не становился узким местом для нестандартных проверок.
	Raw map[string]any `json:"-"`
}

// Parse читает событие со stdin.
func Parse(r io.Reader) (*Event, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var e Event
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(data, &e.Raw)
	return &e, nil
}

// ToolInputField достаёт строковое поле из tool_input.
func (e *Event) ToolInputField(name string) string {
	if len(e.ToolInput) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(e.ToolInput, &m); err != nil {
		return ""
	}
	s, _ := m[name].(string)
	return s
}

// CascadeRoot — директория, от которой движок поднимается вверх, собирая правила.
//
// Для правок файлов отсчёт идёт от самого файла, а не от cwd сессии: иначе
// правило, положенное в подпроект, не сработает, когда его файл правят из корня
// воркспейса — а это основной способ работы.
func (e *Event) CascadeRoot() string {
	switch e.ToolName {
	case "Edit", "Write", "NotebookEdit", "MultiEdit":
		if p := e.ToolInputField("file_path"); p != "" {
			if !filepath.IsAbs(p) {
				p = filepath.Join(e.CWD, p)
			}
			return filepath.Dir(p)
		}
	}
	return e.CWD
}
