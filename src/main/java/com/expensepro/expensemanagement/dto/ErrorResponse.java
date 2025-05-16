package com.expensepro.expensemanagement.dto;

public class ErrorResponse {

    private String message;

    // Constructor
    public ErrorResponse(String message) {
        this.message = message;
    }

    // Getter for message
    public String getMessage() {
        return message;
    }

    // Setter for message
    public void setMessage(String message) {
        this.message = message;
    }
}
