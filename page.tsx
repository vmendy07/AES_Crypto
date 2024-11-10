import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { AlertCircle } from 'lucide-react';

const AESVisualization = () => {
  const [input, setInput] = useState('');
  const [currentStep, setCurrentStep] = useState(0);
  
  // Mock encryption steps (replace with actual data from your Python backend)
  const encryptionSteps = [
    {
      title: "Original Input",
      state: "54776F204F6E65204E696E652054776F",
      description: "Original plaintext converted to hex"
    },
    {
      title: "Initial State",
      state: [
        ["54", "73", "20", "67"],
        ["68", "20", "4b", "20"],
        ["61", "6d", "75", "46"],
        ["74", "79", "6e", "75"]
      ],
      description: "State after hex to state conversion"
    },
    {
      title: "After AddRoundKey",
      state: [
        ["00", "3c", "6e", "47"],
        ["1f", "4e", "22", "74"],
        ["0e", "08", "1b", "31"],
        ["54", "59", "0b", "1a"]
      ],
      description: "State after initial AddRoundKey operation"
    }
    // Add more steps as needed
  ];

  const renderMatrix = (matrix) => {
    if (!Array.isArray(matrix)) return null;
    
    return (
      <div className="grid grid-cols-4 gap-2 max-w-xs mx-auto mt-4">
        {matrix.map((row, i) => (
          row.map((cell, j) => (
            <div
              key={`${i}-${j}`}
              className="bg-blue-100 p-2 text-center font-mono rounded"
            >
              {cell}
            </div>
          ))
        ))}
      </div>
    );
  };

  return (
    <Card className="w-full max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle>AES Encryption Visualization</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {/* Input Section */}
          <div className="flex gap-4">
            <Input
              placeholder="Enter text to encrypt..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="flex-1"
            />
            <Button 
              onClick={() => setCurrentStep(0)}
              className="bg-blue-600 hover:bg-blue-700"
            >
              Encrypt
            </Button>
          </div>

          {/* Navigation */}
          <div className="flex justify-between gap-4">
            <Button
              onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
              disabled={currentStep === 0}
              variant="outline"
            >
              Previous Step
            </Button>
            <Button
              onClick={() => setCurrentStep(Math.min(encryptionSteps.length - 1, currentStep + 1))}
              disabled={currentStep === encryptionSteps.length - 1}
              variant="outline"
            >
              Next Step
            </Button>
          </div>

          {/* Current Step Display */}
          <div className="border rounded-lg p-6 bg-gray-50">
            <h3 className="text-lg font-semibold mb-2 flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-blue-600" />
              {encryptionSteps[currentStep].title}
            </h3>
            <p className="text-gray-600 mb-4">
              {encryptionSteps[currentStep].description}
            </p>
            
            {typeof encryptionSteps[currentStep].state === 'string' ? (
              <div className="bg-white p-4 rounded border font-mono break-all">
                {encryptionSteps[currentStep].state}
              </div>
            ) : (
              renderMatrix(encryptionSteps[currentStep].state)
            )}
          </div>

          {/* Progress Indicator */}
          <div className="flex justify-between items-center mt-4">
            <div className="text-sm text-gray-600">
              Step {currentStep + 1} of {encryptionSteps.length}
            </div>
            <div className="w-64 bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full"
                style={{
                  width: `${((currentStep + 1) / encryptionSteps.length) * 100}%`
                }}
              />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default AESVisualization;