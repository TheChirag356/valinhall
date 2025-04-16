import React from 'react';

type CodeBlockProps = {
  lines: string[];
  highlightLines?: number[];
};

const CodeBlock: React.FC<CodeBlockProps> = ({ lines, highlightLines = [] }) => {
  return (
    <div className="rounded-md overflow-hidden bg-gray-900 text-gray-100 font-mono text-sm my-2">
      <pre className="p-4">
        {lines.map((line, index) => {
          const lineNumber = index + 1;
          const isHighlighted = highlightLines.includes(lineNumber);
          return (
            <div
              key={lineNumber}
              className={`flex ${isHighlighted ? 'bg-red-900 bg-opacity-20' : ''}`}
            >
              <div className="mr-4 text-gray-500 select-none">{lineNumber}</div>
              <div className="whitespace-pre pl-4">{line}</div>
            </div>
          );
        })}
      </pre>
    </div>
  );
};

export { CodeBlock };
