import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateModel } from '../src/services/predictionEngine.js';
import { EVALUATION_DATASET } from '../src/data/evaluationDataset.js';

describe('MAVERICK Evaluation Metrics & Benchmark Suite', () => {
  it('evaluates model against the 65-sample evaluation dataset and strictly separates exact match from novel generalization', async () => {
    const report = await evaluateModel(EVALUATION_DATASET);

    assert.equal(report.totalRecords, 70);
    assert.ok(typeof report.novelAccuracy === 'number');
    assert.ok(report.novelAccuracy >= 0.70 && report.novelAccuracy <= 1.0);
    
    assert.ok(typeof report.macroPrecision === 'number');
    assert.ok(typeof report.macroRecall === 'number');
    assert.ok(typeof report.macroF1Score === 'number');

    // Verify Confusion Matrix is populated
    assert.ok(report.confusionMatrix);
    assert.ok(report.confusionMatrix['Executive BEC (Impersonation)']);
    assert.ok(report.confusionMatrix['Quishing (QR Code Phishing)']);
    assert.ok(report.confusionMatrix['Malware Delivery / Dropper']);
    assert.ok(report.confusionMatrix['Credential Harvesting']);
    assert.ok(report.confusionMatrix['Legitimate / Benign Business']);
    assert.ok(report.confusionMatrix['Newsletter / Promotional Spam']);
    assert.ok(report.confusionMatrix['NO_CONFIDENT_MATCH']);

    // Verify each sample result has positive and negative signals
    for (const sample of report.perSampleResults) {
      assert.ok(sample.id);
      assert.ok(sample.fileName);
      assert.ok(sample.expected);
      assert.ok(sample.predicted);
      assert.ok(typeof sample.correct === 'boolean');
      assert.ok(typeof sample.confidence === 'number');
      assert.ok(Array.isArray(sample.positiveSignals));
      assert.ok(Array.isArray(sample.negativeSignals));
    }
  });
});
