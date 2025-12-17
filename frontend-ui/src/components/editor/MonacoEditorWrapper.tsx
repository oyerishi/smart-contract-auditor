import React, { useRef, useEffect } from 'react';
import Editor from '@monaco-editor/react';

interface MonacoEditorWrapperProps {
  code: string;
  language?: string;
  highlightedLine?: number;
  readOnly?: boolean;
  height?: string;
}

export const MonacoEditorWrapper: React.FC<MonacoEditorWrapperProps> = ({
  code,
  language = 'sol',
  highlightedLine,
  readOnly = true,
  height = '600px',
}) => {
  const editorRef = useRef<any>(null);

  useEffect(() => {
    if (editorRef.current && highlightedLine) {
      // Highlight the specific line
      editorRef.current.revealLineInCenter(highlightedLine);
      editorRef.current.setPosition({ lineNumber: highlightedLine, column: 1 });
      
      // Add decoration to highlight the line
      const decorations = editorRef.current.deltaDecorations(
        [],
        [
          {
            range: {
              startLineNumber: highlightedLine,
              startColumn: 1,
              endLineNumber: highlightedLine,
              endColumn: 1,
            },
            options: {
              isWholeLine: true,
              className: 'highlighted-line',
              glyphMarginClassName: 'highlighted-line-glyph',
            },
          },
        ]
      );

      return () => {
        if (editorRef.current) {
          editorRef.current.deltaDecorations(decorations, []);
        }
      };
    }
  }, [highlightedLine]);

  const handleEditorDidMount = (editor: any) => {
    editorRef.current = editor;
  };

  return (
    <div className="border border-gray-300 rounded-lg overflow-hidden">
      <Editor
        height={height}
        language={language === '.sol' ? 'sol' : 'plaintext'}
        value={code}
        theme="vs-dark"
        onMount={handleEditorDidMount}
        options={{
          readOnly,
          minimap: { enabled: true },
          scrollBeyondLastLine: false,
          fontSize: 14,
          lineNumbers: 'on',
          renderLineHighlight: 'line',
          automaticLayout: true,
        }}
      />
      <style>{`
        .highlighted-line {
          background-color: rgba(239, 68, 68, 0.2);
          border-left: 3px solid #ef4444;
        }
        .highlighted-line-glyph {
          background-color: #ef4444;
          width: 5px !important;
          margin-left: 3px;
        }
      `}</style>
    </div>
  );
};
