const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

/**
 * Handle HTTP response and verify standard errors.
 */
async function handleResponse(response) {
  if (!response.ok) {
    let errorMessage = `API Error: ${response.status} ${response.statusText}`;
    try {
      const errorJson = await response.json();
      if (errorJson && errorJson.error) {
        errorMessage = errorJson.error;
      }
    } catch {
      // Ignore JSON parse failure on error response
    }
    throw new Error(errorMessage);
  }
  
  try {
    return await response.json();
  } catch (err) {
    throw new Error("Failed to parse response from server.");
  }
}

/**
 * Checks a suspicious message for scam indicators.
 * @param {string} text - Message content to check
 * @returns {Promise<Object>} Detection results
 */
export async function checkMessage(text) {
  const response = await fetch(`${API_BASE_URL}/api/check`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text }),
  });
  return handleResponse(response);
}

/**
 * Reports a suspicious scam message to the repository feed.
 * @param {string} text - Reported scam content
 * @param {string} notes - Optional details/metadata
 * @returns {Promise<Object>} Status response
 */
export async function reportScam(text, notes) {
  const response = await fetch(`${API_BASE_URL}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text, notes }),
  });
  return handleResponse(response);
}

/**
 * Fetches the feed of latest scam reports.
 * @returns {Promise<Array>} List of scam report items
 */
export async function getReports() {
  const response = await fetch(`${API_BASE_URL}/api/reports`);
  return handleResponse(response);
}

/**
 * Queries the backend service health status.
 * @returns {Promise<Object>} Status report
 */
export async function getHealth() {
  const response = await fetch(`${API_BASE_URL}/api/health`);
  return handleResponse(response);
}

/**
 * Analyzes a message screenshot using OCR and runs it through the detection pipeline.
 * @param {File} file - Selected screenshot image file
 * @returns {Promise<Object>} Detection results
 */
export async function analyzeScreenshot(file) {
  const formData = new FormData();
  formData.append("file", file);
  const response = await fetch(`${API_BASE_URL}/api/analyze-screenshot`, {
    method: "POST",
    body: formData,
  });
  return handleResponse(response);
}
