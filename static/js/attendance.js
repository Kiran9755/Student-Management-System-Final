const totalInputs = document.querySelectorAll(".total_classes");

const presentInputs = document.querySelectorAll(".present_classes");


totalInputs.forEach((totalInput, index) => {

    const presentInput = presentInputs[index];


    function updatePresentLimit() {

        const total = Number(totalInput.value) || 0;

        presentInput.max = total;

    }


    totalInput.addEventListener("input", updatePresentLimit);

    updatePresentLimit();

});